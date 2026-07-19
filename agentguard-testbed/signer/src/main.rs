use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Signature as AlloySignature, U256};
use alloy_rlp::Decodable;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use thiserror::Error;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub mod proto {
    tonic::include_proto!("aegisledger.signer.v1");
}

use proto::isolated_signer_server::{IsolatedSigner, IsolatedSignerServer};
use proto::{
    PublicIdentityRequest, PublicIdentityResponse, SignAuthorizedTransactionRequest,
    SignAuthorizedTransactionResponse,
};

#[derive(Debug, Error)]
enum AuthorizationError {
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("authorization denied: {0}")]
    Denied(&'static str),
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationEnvelope {
    schema_version: String,
    proposal: ProposalEnvelope,
    decision: DecisionEnvelope,
    reservation_id: String,
    wallet_nonce: u64,
    chain_id: u64,
    transaction: TransactionEnvelope,
    eip712_payload: String,
    eip1559_unsigned_payload: String,
    eip712_hash: String,
    eip1559_hash: String,
    expires_at: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalEnvelope {
    schema_version: String,
    proposal_id: Option<String>,
    principal_id: String,
    wallet: String,
    chain_id: u64,
    asset: String,
    amount: u64,
    intent: IntentEnvelope,
    deadline: String,
    idempotency_key: String,
    mandate_id: Option<String>,
    quote_reference: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum IntentEnvelope {
    #[serde(rename = "transfer")]
    Transfer { recipient: String },
    #[serde(rename = "swap")]
    Swap {
        contract: String,
        selector: String,
        calldata: String,
        minimum_output: u64,
        output_asset: String,
    },
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionEnvelope {
    schema_version: String,
    decision_id: String,
    proposal_hash: String,
    policy_version_id: String,
    policy_hash: String,
    state_version: u64,
    reservation_id: Option<String>,
    verdict: String,
    reason_codes: Vec<String>,
    expires_at: String,
    decision_nonce: String,
    policy_signer: String,
    signature: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionEnvelope {
    operation: String,
    wallet: String,
    chain_id: u64,
    wallet_nonce: u64,
    asset: String,
    amount: u64,
    recipient: Option<String>,
    contract: Option<String>,
    selector: Option<String>,
    calldata: String,
    value: u64,
    gas_limit: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
}

#[derive(Clone, Default)]
struct ReplayState {
    used_decisions: HashSet<String>,
    next_wallet_nonce: HashMap<(String, u64), u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedReplayState {
    schema_version: String,
    used_decisions: Vec<String>,
    wallet_nonces: Vec<PersistedWalletNonce>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedWalletNonce {
    wallet: String,
    chain_id: u64,
    next_nonce: u64,
}

struct SignerService {
    signing_key: SigningKey,
    policy_key: VerifyingKey,
    policy_identity: String,
    signer_identity: String,
    public_key_hex: String,
    build_measurement: String,
    allowed_chains: HashSet<u64>,
    allowed_policy_hashes: HashSet<String>,
    managed_wallets: HashSet<String>,
    replay: Mutex<ReplayState>,
    replay_path: Option<PathBuf>,
}

fn field<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value, AuthorizationError> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or(AuthorizationError::Malformed("required field missing"))?;
    }
    Ok(current)
}

fn string(value: &Value, path: &[&str]) -> Result<String, AuthorizationError> {
    field(value, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or(AuthorizationError::Malformed("field must be a string"))
}

fn number(value: &Value, path: &[&str]) -> Result<u64, AuthorizationError> {
    field(value, path)?
        .as_u64()
        .ok_or(AuthorizationError::Malformed(
            "field must be an unsigned integer",
        ))
}

fn parse_expiry(value: &Value, path: &[&str]) -> Result<DateTime<Utc>, AuthorizationError> {
    let raw = string(value, path)?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| AuthorizationError::Malformed("expiry must be RFC 3339"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AuthorizationError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| AuthorizationError::Malformed("invalid hexadecimal value"))
}

fn hash_json(value: &Value) -> Result<String, AuthorizationError> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|_| AuthorizationError::Malformed("JSON cannot be canonicalized"))?;
    Ok(format!("0x{:x}", Sha256::digest(canonical)))
}

fn hash_proposal_json(value: &Value) -> Result<String, AuthorizationError> {
    fn remove_null_object_fields(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.retain(|_, child| !child.is_null());
                for child in object.values_mut() {
                    remove_null_object_fields(child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    remove_null_object_fields(item);
                }
            }
            _ => {}
        }
    }

    let mut proposal = value.clone();
    remove_null_object_fields(&mut proposal);
    hash_json(&proposal)
}

fn ethereum_address(public_key: &[u8]) -> String {
    let hash = Keccak256::digest(&public_key[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

fn policy_address(public_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    format!("0x{}", hex::encode(&digest[12..]))
}

fn load_signing_key_from_file(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err("signing key path must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("signing key file must not be writable by group or other users".into());
        }
    }
    if metadata.len() > 1024 {
        return Err("signing key file is unexpectedly large".into());
    }
    let encoded = fs::read_to_string(path)?;
    let decoded = decode_hex(encoded.trim()).map_err(|error| error.to_string())?;
    let private_key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "signing key file must contain exactly 32 bytes")?;
    SigningKey::from_bytes((&private_key).into()).map_err(Into::into)
}

fn load_replay_state(path: &Path) -> Result<ReplayState, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(ReplayState::default());
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err("replay state must be a regular file no larger than 16 MiB".into());
    }
    let persisted: PersistedReplayState = serde_json::from_slice(&fs::read(path)?)?;
    if persisted.schema_version != "aegisledger.signer_replay.v1" {
        return Err("unsupported replay state schema".into());
    }
    let mut state = ReplayState {
        used_decisions: persisted.used_decisions.into_iter().collect(),
        next_wallet_nonce: HashMap::new(),
    };
    for entry in persisted.wallet_nonces {
        let key = (entry.wallet.to_lowercase(), entry.chain_id);
        if state
            .next_wallet_nonce
            .insert(key, entry.next_nonce)
            .is_some()
        {
            return Err("duplicate wallet nonce entry in replay state".into());
        }
    }
    Ok(state)
}

fn persist_replay_state(
    path: &Path,
    state: &ReplayState,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut used_decisions: Vec<_> = state.used_decisions.iter().cloned().collect();
    used_decisions.sort();
    let mut wallet_nonces: Vec<_> = state
        .next_wallet_nonce
        .iter()
        .map(|((wallet, chain_id), next_nonce)| PersistedWalletNonce {
            wallet: wallet.clone(),
            chain_id: *chain_id,
            next_nonce: *next_nonce,
        })
        .collect();
    wallet_nonces
        .sort_by(|left, right| (&left.wallet, left.chain_id).cmp(&(&right.wallet, right.chain_id)));
    let persisted = PersistedReplayState {
        schema_version: "aegisledger.signer_replay.v1".to_owned(),
        used_decisions,
        wallet_nonces,
    };
    let bytes = serde_json::to_vec(&persisted)?;
    let temporary_path = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary_path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary_path, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn parse_authorization(value: &[u8]) -> Result<Value, AuthorizationError> {
    let envelope: AuthorizationEnvelope = serde_json::from_slice(value)
        .map_err(|_| AuthorizationError::Malformed("authorization schema is invalid"))?;
    if envelope.schema_version != "aegisledger.sign_request.v1"
        || envelope.proposal.schema_version != "aegisledger.proposal.v1"
        || envelope.decision.schema_version != "aegisledger.decision.v1"
    {
        return Err(AuthorizationError::Malformed(
            "authorization schema version is unsupported",
        ));
    }
    serde_json::from_slice(value)
        .map_err(|_| AuthorizationError::Malformed("authorization_json is invalid"))
}

fn decode_eip1559(value: &str) -> Result<TxEip1559, AuthorizationError> {
    let encoded = decode_hex(value)?;
    if encoded.first() != Some(&0x02) {
        return Err(AuthorizationError::Denied(
            "unsigned transaction is not EIP-1559",
        ));
    }
    let mut payload = &encoded[1..];
    let transaction = TxEip1559::decode(&mut payload)
        .map_err(|_| AuthorizationError::Malformed("invalid EIP-1559 RLP payload"))?;
    if !payload.is_empty() || transaction.encoded_for_signing() != encoded {
        return Err(AuthorizationError::Denied(
            "unsigned transaction is not canonical EIP-1559",
        ));
    }
    Ok(transaction)
}

impl SignerService {
    fn verify_decision(&self, root: &Value) -> Result<(), AuthorizationError> {
        let decision = field(root, &["decision"])?;
        let signature = decode_hex(&string(decision, &["signature"])?)?;
        let signature = Ed25519Signature::from_slice(&signature)
            .map_err(|_| AuthorizationError::Malformed("invalid decision signature length"))?;
        let mut unsigned = decision
            .as_object()
            .cloned()
            .ok_or(AuthorizationError::Malformed("decision must be an object"))?;
        unsigned.remove("signature");
        let canonical = serde_jcs::to_vec(&Value::Object(unsigned))
            .map_err(|_| AuthorizationError::Malformed("decision cannot be canonicalized"))?;
        self.policy_key
            .verify(&canonical, &signature)
            .map_err(|_| AuthorizationError::Denied("invalid policy-service signature"))?;

        if string(decision, &["policy_signer"])?.to_lowercase() != self.policy_identity {
            return Err(AuthorizationError::Denied(
                "policy signer identity mismatch",
            ));
        }
        if string(decision, &["verdict"])? != "ALLOW" {
            return Err(AuthorizationError::Denied("decision verdict is not ALLOW"));
        }
        if parse_expiry(decision, &["expires_at"])? <= Utc::now() {
            return Err(AuthorizationError::Denied("decision expired"));
        }
        let policy_hash = string(decision, &["policy_hash"])?.to_lowercase();
        if !self.allowed_policy_hashes.is_empty()
            && !self.allowed_policy_hashes.contains(&policy_hash)
        {
            return Err(AuthorizationError::Denied("policy hash is not approved"));
        }
        Ok(())
    }

    fn verify_binding(&self, root: &Value) -> Result<(), AuthorizationError> {
        let proposal = field(root, &["proposal"])?;
        let decision = field(root, &["decision"])?;
        let transaction = field(root, &["transaction"])?;
        if hash_proposal_json(proposal)? != string(decision, &["proposal_hash"])?.to_lowercase() {
            return Err(AuthorizationError::Denied("proposal hash mismatch"));
        }
        if string(root, &["reservation_id"])? != string(decision, &["reservation_id"])? {
            return Err(AuthorizationError::Denied("reservation mismatch"));
        }

        let chain_id = number(root, &["chain_id"])?;
        if !self.allowed_chains.contains(&chain_id)
            || number(proposal, &["chain_id"])? != chain_id
            || number(transaction, &["chain_id"])? != chain_id
        {
            return Err(AuthorizationError::Denied("chain binding mismatch"));
        }
        let wallet = string(proposal, &["wallet"])?.to_lowercase();
        if string(transaction, &["wallet"])?.to_lowercase() != wallet {
            return Err(AuthorizationError::Denied("wallet binding mismatch"));
        }
        if wallet != self.signer_identity {
            return Err(AuthorizationError::Denied(
                "wallet does not match signer identity",
            ));
        }
        if !self.managed_wallets.is_empty() && !self.managed_wallets.contains(&wallet) {
            return Err(AuthorizationError::Denied(
                "wallet is not managed by this signer",
            ));
        }
        if number(root, &["wallet_nonce"])? != number(transaction, &["wallet_nonce"])? {
            return Err(AuthorizationError::Denied("wallet nonce binding mismatch"));
        }
        if string(proposal, &["asset"])? != string(transaction, &["asset"])?
            || number(proposal, &["amount"])? != number(transaction, &["amount"])?
        {
            return Err(AuthorizationError::Denied(
                "asset or amount binding mismatch",
            ));
        }

        let kind = string(proposal, &["intent", "kind"])?;
        if string(transaction, &["operation"])? != kind {
            return Err(AuthorizationError::Denied("operation binding mismatch"));
        }
        if kind == "transfer" {
            if string(proposal, &["intent", "recipient"])?.to_lowercase()
                != string(transaction, &["recipient"])?.to_lowercase()
            {
                return Err(AuthorizationError::Denied("recipient binding mismatch"));
            }
            if string(transaction, &["asset"])? != format!("NATIVE:{chain_id}")
                || number(transaction, &["value"])? != number(transaction, &["amount"])?
                || string(transaction, &["calldata"])? != "0x"
            {
                return Err(AuthorizationError::Denied(
                    "native transfer economic binding mismatch",
                ));
            }
        } else if string(proposal, &["intent", "contract"])?.to_lowercase()
            != string(transaction, &["contract"])?.to_lowercase()
            || string(proposal, &["intent", "selector"])?.to_lowercase()
                != string(transaction, &["selector"])?.to_lowercase()
            || string(proposal, &["intent", "calldata"])?.to_lowercase()
                != string(transaction, &["calldata"])?.to_lowercase()
        {
            return Err(AuthorizationError::Denied("contract call binding mismatch"));
        }

        let request_expiry = parse_expiry(root, &["expires_at"])?;
        if request_expiry <= Utc::now()
            || request_expiry > parse_expiry(decision, &["expires_at"])?
            || request_expiry > parse_expiry(proposal, &["deadline"])?
        {
            return Err(AuthorizationError::Denied(
                "request expiry is outside authorization",
            ));
        }

        let raw_transaction = decode_eip1559(&string(root, &["eip1559_unsigned_payload"])?)?;
        if raw_transaction.chain_id != chain_id
            || raw_transaction.nonce != number(transaction, &["wallet_nonce"])?
        {
            return Err(AuthorizationError::Denied(
                "raw transaction chain or nonce binding mismatch",
            ));
        }
        if raw_transaction.gas_limit != number(transaction, &["gas_limit"])?
            || raw_transaction.max_fee_per_gas
                != u128::from(number(transaction, &["max_fee_per_gas"])?)
            || raw_transaction.max_priority_fee_per_gas
                != u128::from(number(transaction, &["max_priority_fee_per_gas"])?)
        {
            return Err(AuthorizationError::Denied(
                "raw transaction gas or fee binding mismatch",
            ));
        }
        let target = if kind == "transfer" {
            string(transaction, &["recipient"])?
        } else {
            string(transaction, &["contract"])?
        }
        .parse::<Address>()
        .map_err(|_| AuthorizationError::Malformed("transaction target is not an address"))?;
        if raw_transaction.to.to() != Some(&target) {
            return Err(AuthorizationError::Denied(
                "raw transaction recipient or contract binding mismatch",
            ));
        }
        if raw_transaction.value != U256::from(number(transaction, &["value"])?) {
            return Err(AuthorizationError::Denied(
                "raw transaction value binding mismatch",
            ));
        }
        let calldata = decode_hex(&string(transaction, &["calldata"])?)?;
        if raw_transaction.input.as_ref() != calldata.as_slice() {
            return Err(AuthorizationError::Denied(
                "raw transaction calldata binding mismatch",
            ));
        }
        if !raw_transaction.access_list.is_empty() {
            return Err(AuthorizationError::Denied(
                "raw transaction access list is not authorized",
            ));
        }

        let eip1559_hash = format!("{:#x}", raw_transaction.signature_hash());
        if eip1559_hash != string(root, &["eip1559_hash"])?.to_lowercase() {
            return Err(AuthorizationError::Denied("EIP-1559 digest mismatch"));
        }
        let eip712 = decode_hex(&string(root, &["eip712_payload"])?)?;
        let proposal_hash = decode_hex(&string(decision, &["proposal_hash"])?)?;
        if eip712.len() != 66 || !eip712.starts_with(&[0x19, 0x01]) || eip712[34..] != proposal_hash
        {
            return Err(AuthorizationError::Denied(
                "typed-data payload is not bound to the authorized proposal",
            ));
        }
        let eip712_hash = format!("0x{:x}", Keccak256::digest(&eip712));
        if eip712_hash != string(root, &["eip712_hash"])?.to_lowercase() {
            return Err(AuthorizationError::Denied("EIP-712 digest mismatch"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl IsolatedSigner for SignerService {
    async fn public_identity(
        &self,
        _request: Request<PublicIdentityRequest>,
    ) -> Result<Response<PublicIdentityResponse>, Status> {
        Ok(Response::new(PublicIdentityResponse {
            signer_identity: self.signer_identity.clone(),
            secp256k1_public_key: self.public_key_hex.clone(),
            build_measurement: self.build_measurement.clone(),
        }))
    }

    async fn sign_authorized_transaction(
        &self,
        request: Request<SignAuthorizedTransactionRequest>,
    ) -> Result<Response<SignAuthorizedTransactionResponse>, Status> {
        let root = parse_authorization(&request.into_inner().authorization_json)
            .map_err(|_| Status::invalid_argument("authorization_json schema is invalid"))?;
        self.verify_decision(&root).map_err(|error| {
            warn!(reason = %error, "sign request denied");
            Status::permission_denied("authorization denied")
        })?;
        self.verify_binding(&root).map_err(|error| {
            warn!(reason = %error, "transaction binding denied");
            Status::permission_denied("authorization denied")
        })?;

        let decision_nonce = string(&root, &["decision", "decision_nonce"])
            .map_err(|_| Status::invalid_argument("decision nonce missing"))?;
        let wallet = string(&root, &["proposal", "wallet"])
            .map_err(|_| Status::invalid_argument("wallet missing"))?
            .to_lowercase();
        let chain_id = number(&root, &["chain_id"])
            .map_err(|_| Status::invalid_argument("chain id missing"))?;
        let wallet_nonce = number(&root, &["wallet_nonce"])
            .map_err(|_| Status::invalid_argument("wallet nonce missing"))?;

        let mut replay = self.replay.lock().await;
        if replay.used_decisions.contains(&decision_nonce) {
            return Err(Status::permission_denied("decision replay detected"));
        }
        let expected_nonce = replay
            .next_wallet_nonce
            .get(&(wallet.clone(), chain_id))
            .copied()
            .unwrap_or(0);
        if wallet_nonce != expected_nonce {
            return Err(Status::permission_denied("wallet nonce is not monotonic"));
        }

        let mut updated_replay = replay.clone();
        updated_replay.used_decisions.insert(decision_nonce.clone());
        updated_replay
            .next_wallet_nonce
            .insert((wallet.clone(), chain_id), wallet_nonce + 1);
        if let Some(path) = self.replay_path.as_deref() {
            persist_replay_state(path, &updated_replay).map_err(|error| {
                warn!(reason = %error, "failed to persist replay state");
                Status::unavailable("replay state persistence failed")
            })?;
        }
        *replay = updated_replay;
        drop(replay);

        let digest_hex = string(&root, &["eip1559_hash"])
            .map_err(|_| Status::invalid_argument("transaction digest missing"))?;
        let digest = decode_hex(&digest_hex)
            .map_err(|_| Status::invalid_argument("transaction digest invalid"))?;
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .map_err(|_| Status::internal("signing failure"))?;
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        let raw_transaction = decode_eip1559(
            &string(&root, &["eip1559_unsigned_payload"])
                .map_err(|_| Status::invalid_argument("unsigned transaction missing"))?,
        )
        .map_err(|_| Status::invalid_argument("unsigned transaction invalid"))?;
        let signed_transaction =
            raw_transaction.into_signed(AlloySignature::from((signature, recovery_id)));
        let transaction_hash = format!("{:#x}", signed_transaction.hash());
        let signed_transaction_bytes = signed_transaction.encoded_2718();

        let evidence_unsigned = json!({
            "schema_version": "aegisledger.enclave_evidence.v1",
            "mode": "local-process-or-nitro",
            "build_measurement": self.build_measurement,
            "signer_identity": self.signer_identity,
            "secp256k1_public_key": self.public_key_hex,
            "transaction_hash": transaction_hash,
            "signing_hash": digest_hex,
            "proposal_hash": string(&root, &["decision", "proposal_hash"])
                .map_err(|_| Status::invalid_argument("proposal hash missing"))?,
            "policy_version_id": string(&root, &["decision", "policy_version_id"])
                .map_err(|_| Status::invalid_argument("policy version missing"))?,
            "policy_hash": string(&root, &["decision", "policy_hash"])
                .map_err(|_| Status::invalid_argument("policy hash missing"))?,
            "state_version": number(&root, &["decision", "state_version"])
                .map_err(|_| Status::invalid_argument("state version missing"))?,
            "reservation_id": string(&root, &["reservation_id"])
                .map_err(|_| Status::invalid_argument("reservation missing"))?,
            "wallet": string(&root, &["proposal", "wallet"])
                .map_err(|_| Status::invalid_argument("wallet missing"))?,
            "principal_id": string(&root, &["proposal", "principal_id"])
                .map_err(|_| Status::invalid_argument("principal missing"))?,
            "chain_id": chain_id,
            "wallet_nonce": wallet_nonce,
            "decision_id": string(&root, &["decision", "decision_id"])
                .map_err(|_| Status::invalid_argument("decision id missing"))?,
            "decision_nonce": decision_nonce,
            "expires_at": parse_expiry(&root, &["expires_at"])
                .map_err(|_| Status::invalid_argument("expiry missing"))?
                .to_rfc3339_opts(SecondsFormat::AutoSi, true),
            "issued_at": Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        });
        let evidence_canonical = serde_jcs::to_vec(&evidence_unsigned)
            .map_err(|_| Status::internal("evidence canonicalization failure"))?;
        let evidence_digest = Sha256::digest(evidence_canonical);
        let (evidence_signature, evidence_recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&evidence_digest)
            .map_err(|_| Status::internal("evidence signing failure"))?;
        let mut evidence_signature_bytes = evidence_signature.to_bytes().to_vec();
        evidence_signature_bytes.push(evidence_recovery_id.to_byte());
        let mut evidence = evidence_unsigned;
        evidence["evidence_hash"] = json!(format!("0x{}", hex::encode(evidence_digest)));
        evidence["evidence_signature"] =
            json!(format!("0x{}", hex::encode(evidence_signature_bytes)));
        info!(chain_id, wallet_nonce, "authorized transaction signed");
        Ok(Response::new(SignAuthorizedTransactionResponse {
            eip1559_hash: digest_hex.clone(),
            wallet_nonce,
            chain_id,
            decision_id: string(&root, &["decision", "decision_id"])
                .map_err(|_| Status::invalid_argument("decision id missing"))?,
            signer_identity: self.signer_identity.clone(),
            signature: format!("0x{}", hex::encode(signature_bytes)),
            enclave_evidence_json: serde_json::to_vec(&evidence)
                .map_err(|_| Status::internal("evidence serialization failure"))?,
            signed_transaction: signed_transaction_bytes,
            transaction_hash,
            signing_hash: digest_hex,
        }))
    }
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn csv_set(name: &str) -> HashSet<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let policy_key_bytes = decode_hex(&required_env("AEGIS_POLICY_PUBLIC_KEY_HEX")?)?;
    let policy_key_array: [u8; 32] = policy_key_bytes
        .try_into()
        .map_err(|_| "AEGIS_POLICY_PUBLIC_KEY_HEX must contain 32 bytes")?;
    let policy_key = VerifyingKey::from_bytes(&policy_key_array)?;
    let policy_identity = policy_address(&policy_key);

    let signing_key_path = PathBuf::from(required_env("AEGIS_SIGNER_PRIVATE_KEY_FILE")?);
    let signing_key = load_signing_key_from_file(&signing_key_path)?;
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key_hex = format!("0x{}", hex::encode(public_key.as_bytes()));
    let signer_identity = ethereum_address(public_key.as_bytes());
    let build_measurement = env::var("AEGIS_SIGNER_BUILD_MEASUREMENT")
        .unwrap_or_else(|_| "development-unmeasured".to_owned());
    let allowed_chains = csv_set("AEGIS_ALLOWED_CHAIN_IDS")
        .into_iter()
        .map(|value| value.parse::<u64>())
        .collect::<Result<HashSet<_>, _>>()?;
    if allowed_chains.is_empty() {
        return Err("AEGIS_ALLOWED_CHAIN_IDS must not be empty".into());
    }

    let replay_path = PathBuf::from(required_env("AEGIS_SIGNER_REPLAY_STATE_FILE")?);
    let replay_state = load_replay_state(&replay_path)?;
    let service = Arc::new(SignerService {
        signing_key,
        policy_key,
        policy_identity,
        signer_identity,
        public_key_hex,
        build_measurement,
        allowed_chains,
        allowed_policy_hashes: csv_set("AEGIS_ALLOWED_POLICY_HASHES"),
        managed_wallets: csv_set("AEGIS_MANAGED_WALLETS"),
        replay: Mutex::new(replay_state),
        replay_path: Some(replay_path),
    });

    let certificate = fs::read(required_env("AEGIS_TLS_CERT")?)?;
    let private_key = fs::read(required_env("AEGIS_TLS_KEY")?)?;
    let client_ca = fs::read(required_env("AEGIS_CLIENT_CA")?)?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .client_ca_root(Certificate::from_pem(client_ca));
    let address: SocketAddr = env::var("AEGIS_SIGNER_BIND")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_owned())
        .parse()?;
    info!(%address, identity = %service.signer_identity, "isolated signer starting");
    Server::builder()
        .tls_config(tls)?
        .add_service(IsolatedSignerServer::from_arc(service))
        .serve_with_shutdown(address, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_primitives::{Address, Bytes, TxKind, U256};
    use ed25519_dalek::{Signer, SigningKey as PolicySigningKey};
    use serde_json::Map;
    use std::path::PathBuf;

    const AUTHORIZED_RECIPIENT: &str = "0x3434343434343434343434343434343434343434";
    const SUBSTITUTED_RECIPIENT: &str = "0x5656565656565656565656565656565656565656";

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegisledger-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ))
    }

    fn wallet() -> String {
        let signing_key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
        ethereum_address(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
    }

    fn service() -> SignerService {
        let policy_signing_key = PolicySigningKey::from_bytes(&[7; 32]);
        let policy_key = policy_signing_key.verifying_key();
        let transaction_signing_key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
        let public_key = transaction_signing_key
            .verifying_key()
            .to_encoded_point(false);
        SignerService {
            signing_key: transaction_signing_key,
            policy_key,
            policy_identity: policy_address(&policy_key),
            signer_identity: ethereum_address(public_key.as_bytes()),
            public_key_hex: format!("0x{}", hex::encode(public_key.as_bytes())),
            build_measurement: "test-build".to_owned(),
            allowed_chains: HashSet::from([31_337]),
            allowed_policy_hashes: HashSet::new(),
            managed_wallets: HashSet::from([wallet()]),
            replay: Mutex::new(ReplayState::default()),
            replay_path: None,
        }
    }

    fn authorization_with_raw_recipient(raw_recipient: &str) -> Value {
        let now = Utc::now();
        let expiry =
            (now + chrono::Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::AutoSi, true);
        let proposal = json!({
            "schema_version": "aegisledger.proposal.v1",
            "principal_id": "researcher",
            "wallet": wallet(),
            "chain_id": 31_337,
            "asset": "NATIVE:31337",
            "amount": 100,
            "intent": {"kind": "transfer", "recipient": AUTHORIZED_RECIPIENT},
            "deadline": expiry,
            "idempotency_key": "rust-signer-regression"
        });
        let proposal_hash = hash_json(&proposal).unwrap();
        let raw_transaction = TxEip1559 {
            chain_id: 31_337,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            to: TxKind::Call(raw_recipient.parse::<Address>().unwrap()),
            value: U256::from(100),
            access_list: Default::default(),
            input: Bytes::new(),
        }
        .encoded_for_signing();
        let eip1559_payload = format!("0x{}", hex::encode(&raw_transaction));
        let eip712_payload = format!("0x1901{}{}", "ab".repeat(32), &proposal_hash[2..]);
        let mut decision = Map::new();
        decision.insert(
            "schema_version".to_owned(),
            json!("aegisledger.decision.v1"),
        );
        decision.insert(
            "decision_id".to_owned(),
            json!("01980d25-e947-7000-8000-000000000001"),
        );
        decision.insert("proposal_hash".to_owned(), json!(proposal_hash));
        decision.insert(
            "policy_version_id".to_owned(),
            json!("01980d25-e947-7000-8000-000000000002"),
        );
        decision.insert(
            "policy_hash".to_owned(),
            json!(format!("0x{}", "44".repeat(32))),
        );
        decision.insert("state_version".to_owned(), json!(1));
        decision.insert(
            "reservation_id".to_owned(),
            json!("8e42975e-4ef8-4bb8-bf8e-34ec6c8fb084"),
        );
        decision.insert("verdict".to_owned(), json!("ALLOW"));
        decision.insert("reason_codes".to_owned(), json!(["AUTHORIZED"]));
        decision.insert("expires_at".to_owned(), json!(expiry));
        decision.insert(
            "decision_nonce".to_owned(),
            json!("01980d25-e947-7000-8000-000000000003"),
        );
        let policy_signing_key = PolicySigningKey::from_bytes(&[7; 32]);
        decision.insert(
            "policy_signer".to_owned(),
            json!(policy_address(&policy_signing_key.verifying_key())),
        );
        let canonical_decision = serde_jcs::to_vec(&Value::Object(decision.clone())).unwrap();
        decision.insert(
            "signature".to_owned(),
            json!(hex::encode(
                policy_signing_key.sign(&canonical_decision).to_bytes()
            )),
        );

        json!({
            "schema_version": "aegisledger.sign_request.v1",
            "proposal": proposal,
            "decision": Value::Object(decision),
            "reservation_id": "8e42975e-4ef8-4bb8-bf8e-34ec6c8fb084",
            "wallet_nonce": 0,
            "chain_id": 31_337,
            "transaction": {
                "operation": "transfer",
                "wallet": wallet(),
                "chain_id": 31_337,
                "wallet_nonce": 0,
                "asset": "NATIVE:31337",
                "amount": 100,
                "recipient": AUTHORIZED_RECIPIENT,
                "contract": null,
                "selector": null,
                "calldata": "0x",
                "value": 100,
                "gas_limit": 100_000,
                "max_fee_per_gas": 1_000_000_000_u64,
                "max_priority_fee_per_gas": 100_000_000_u64
            },
            "eip712_payload": eip712_payload,
            "eip1559_unsigned_payload": eip1559_payload,
            "eip712_hash": format!("0x{:x}", Keccak256::digest(decode_hex(&eip712_payload).unwrap())),
            "eip1559_hash": format!("0x{:x}", Keccak256::digest(&raw_transaction)),
            "expires_at": expiry
        })
    }

    #[test]
    fn rejects_raw_eip1559_recipient_substitution() {
        let authorization = authorization_with_raw_recipient(SUBSTITUTED_RECIPIENT);

        let error = service().verify_binding(&authorization).unwrap_err();

        assert!(error.to_string().contains("recipient"));
    }

    #[test]
    fn rejects_wallet_claim_that_is_not_derived_signer_identity() {
        let mut authorization = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        let claimed_wallet = "0x7878787878787878787878787878787878787878";
        authorization["proposal"]["wallet"] = json!(claimed_wallet);
        authorization["transaction"]["wallet"] = json!(claimed_wallet);
        let proposal_hash = hash_json(&authorization["proposal"]).unwrap();
        authorization["decision"]["proposal_hash"] = json!(proposal_hash);
        let eip712 = format!("0x1901{}{}", "ab".repeat(32), &proposal_hash[2..]);
        authorization["eip712_payload"] = json!(eip712);
        authorization["eip712_hash"] = json!(format!(
            "0x{:x}",
            Keccak256::digest(decode_hex(&eip712).unwrap())
        ));

        let error = service().verify_binding(&authorization).unwrap_err();

        assert!(error.to_string().contains("signer identity"));
    }

    #[test]
    fn proposal_hash_ignores_optional_transport_nulls() {
        let mut authorization = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        authorization["proposal"]["mandate_id"] = Value::Null;
        authorization["proposal"]["quote_reference"] = Value::Null;

        service().verify_binding(&authorization).unwrap();
    }

    #[test]
    fn accepts_exact_canonical_transaction_and_proposal_bound_typed_data() {
        let authorization = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        let signer = service();

        signer.verify_decision(&authorization).unwrap();
        signer.verify_binding(&authorization).unwrap();
    }

    #[test]
    fn rejects_raw_value_gas_fee_and_calldata_substitution() {
        for field_name in ["value", "gas_limit", "max_fee_per_gas", "calldata"] {
            let mut authorization = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
            let mut transaction =
                decode_eip1559(authorization["eip1559_unsigned_payload"].as_str().unwrap())
                    .unwrap();
            match field_name {
                "value" => transaction.value = U256::from(1),
                "gas_limit" => transaction.gas_limit += 1,
                "max_fee_per_gas" => transaction.max_fee_per_gas += 1,
                "calldata" => transaction.input = Bytes::from_static(&[0xde, 0xad]),
                _ => unreachable!(),
            }
            let encoded = transaction.encoded_for_signing();
            authorization["eip1559_unsigned_payload"] =
                json!(format!("0x{}", hex::encode(&encoded)));
            authorization["eip1559_hash"] = json!(format!("0x{:x}", Keccak256::digest(&encoded)));

            assert!(
                service().verify_binding(&authorization).is_err(),
                "{field_name}"
            );
        }
    }

    #[test]
    fn rejects_unbound_eip712_payload_and_trailing_rlp_bytes() {
        let mut unbound_typed_data = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        let eip712 = format!("0x1901{}{}", "ab".repeat(32), "cd".repeat(32));
        unbound_typed_data["eip712_payload"] = json!(eip712);
        unbound_typed_data["eip712_hash"] = json!(format!(
            "0x{:x}",
            Keccak256::digest(decode_hex(&eip712).unwrap())
        ));
        assert!(service().verify_binding(&unbound_typed_data).is_err());

        let mut trailing_bytes = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        let mut raw =
            decode_hex(trailing_bytes["eip1559_unsigned_payload"].as_str().unwrap()).unwrap();
        raw.push(0);
        trailing_bytes["eip1559_unsigned_payload"] = json!(format!("0x{}", hex::encode(&raw)));
        trailing_bytes["eip1559_hash"] = json!(format!("0x{:x}", Keccak256::digest(&raw)));
        assert!(service().verify_binding(&trailing_bytes).is_err());
    }

    #[test]
    fn rejects_unknown_duplicate_and_unsupported_schema_fields() {
        let mut unknown = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        unknown["unexpected"] = json!(true);
        assert!(parse_authorization(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let valid =
            serde_json::to_string(&authorization_with_raw_recipient(AUTHORIZED_RECIPIENT)).unwrap();
        let duplicate = valid.replacen(
            "\"wallet_nonce\":0",
            "\"wallet_nonce\":0,\"wallet_nonce\":0",
            1,
        );
        assert!(parse_authorization(duplicate.as_bytes()).is_err());

        let mut unsupported = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        unsupported["schema_version"] = json!("aegisledger.sign_request.v2");
        assert!(parse_authorization(&serde_json::to_vec(&unsupported).unwrap()).is_err());
    }

    #[tokio::test]
    async fn returns_broadcastable_signed_transaction_and_network_hash() {
        let authorization = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        let expected_signing_hash = authorization["eip1559_hash"].as_str().unwrap().to_owned();
        let response = service()
            .sign_authorized_transaction(Request::new(SignAuthorizedTransactionRequest {
                authorization_json: serde_json::to_vec(&authorization).unwrap(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.signing_hash, expected_signing_hash);
        assert_eq!(response.eip1559_hash, expected_signing_hash);
        assert_eq!(response.signature.len(), 132);
        assert_eq!(response.signed_transaction.first(), Some(&0x02));
        assert_eq!(
            response.transaction_hash,
            format!("0x{:x}", Keccak256::digest(&response.signed_transaction))
        );
        let evidence: Value = serde_json::from_slice(&response.enclave_evidence_json).unwrap();
        assert_eq!(evidence["transaction_hash"], response.transaction_hash);
        assert_eq!(evidence["signing_hash"], response.signing_hash);
    }

    #[test]
    fn loads_a_stable_signing_key_from_a_file() {
        let path = test_path("signing-key");
        fs::write(&path, format!("0x{}\n", "09".repeat(32))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let first = load_signing_key_from_file(&path).unwrap();
        let second = load_signing_key_from_file(&path).unwrap();

        assert_eq!(first.to_bytes(), second.to_bytes());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn replay_state_round_trips_to_durable_storage() {
        let path = test_path("replay-state");
        let mut state = ReplayState::default();
        state.used_decisions.insert("decision-1".to_owned());
        state.next_wallet_nonce.insert((wallet(), 31_337), 9);

        persist_replay_state(&path, &state).unwrap();
        let recovered = load_replay_state(&path).unwrap();

        assert!(recovered.used_decisions.contains("decision-1"));
        assert_eq!(
            recovered.next_wallet_nonce.get(&(wallet(), 31_337)),
            Some(&9)
        );
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn consumed_decision_is_rejected_after_signer_restart() {
        let path = test_path("restart-replay-state");
        let authorization = authorization_with_raw_recipient(AUTHORIZED_RECIPIENT);
        let request = || {
            Request::new(SignAuthorizedTransactionRequest {
                authorization_json: serde_json::to_vec(&authorization).unwrap(),
            })
        };
        let mut first = service();
        first.replay_path = Some(path.clone());
        first.sign_authorized_transaction(request()).await.unwrap();

        let mut restarted = service();
        restarted.replay = Mutex::new(load_replay_state(&path).unwrap());
        restarted.replay_path = Some(path.clone());
        let error = restarted
            .sign_authorized_transaction(request())
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(error.message().contains("replay"));
        fs::remove_file(path).unwrap();
    }
}
