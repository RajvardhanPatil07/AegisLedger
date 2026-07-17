use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
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

#[derive(Default)]
struct ReplayState {
    used_decisions: HashSet<String>,
    next_wallet_nonce: HashMap<(String, u64), u64>,
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

fn ethereum_address(public_key: &[u8]) -> String {
    let hash = Keccak256::digest(&public_key[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

fn policy_address(public_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    format!("0x{}", hex::encode(&digest[12..]))
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
        if hash_json(proposal)? != string(decision, &["proposal_hash"])?.to_lowercase() {
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

        let typed = string(root, &["eip1559_unsigned_payload"])?;
        let typed_bytes = decode_hex(&typed)?;
        if typed_bytes.first() != Some(&0x02) {
            return Err(AuthorizationError::Denied(
                "unsigned transaction is not EIP-1559",
            ));
        }
        let eip1559_hash = format!("0x{:x}", Keccak256::digest(&typed_bytes));
        if eip1559_hash != string(root, &["eip1559_hash"])?.to_lowercase() {
            return Err(AuthorizationError::Denied("EIP-1559 digest mismatch"));
        }
        let eip712 = decode_hex(&string(root, &["eip712_payload"])?)?;
        if !eip712.starts_with(&[0x19, 0x01]) {
            return Err(AuthorizationError::Denied(
                "typed-data payload is not EIP-712",
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
        let root: Value = serde_json::from_slice(&request.into_inner().authorization_json)
            .map_err(|_| Status::invalid_argument("authorization_json is invalid"))?;
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

        replay.used_decisions.insert(decision_nonce.clone());
        replay
            .next_wallet_nonce
            .insert((wallet, chain_id), wallet_nonce + 1);
        drop(replay);

        let evidence = json!({
            "schema_version": "aegisledger.enclave_evidence.v1",
            "mode": "local-process-or-nitro",
            "build_measurement": self.build_measurement,
            "signer_identity": self.signer_identity,
            "decision_nonce": decision_nonce,
            "issued_at": Utc::now().to_rfc3339(),
        });
        info!(chain_id, wallet_nonce, "authorized transaction signed");
        Ok(Response::new(SignAuthorizedTransactionResponse {
            eip1559_hash: digest_hex,
            wallet_nonce,
            chain_id,
            decision_id: string(&root, &["decision", "decision_id"])
                .map_err(|_| Status::invalid_argument("decision id missing"))?,
            signer_identity: self.signer_identity.clone(),
            signature: format!("0x{}", hex::encode(signature_bytes)),
            enclave_evidence_json: serde_json::to_vec(&evidence)
                .map_err(|_| Status::internal("evidence serialization failure"))?,
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

    let signing_key = SigningKey::random(&mut OsRng);
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
        replay: Mutex::new(ReplayState::default()),
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
