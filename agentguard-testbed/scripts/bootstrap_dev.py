#!/usr/bin/env python3
"""Generate local-only credentials and mTLS identities without tracking secrets."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from eth_hash.auto import keccak

from aegisledger.policy import PolicyV1
from agentwallet.chain.crypto import KeyPair

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env.local"
CERT_DIR = ROOT / "artifacts" / "dev-certs"
SIGNER_SECRET_DIR = ROOT / "artifacts" / "dev-signer"
DEVELOPMENT_POLICY_DIR = ROOT / "artifacts" / "dev-policy"


def token() -> str:
    return secrets.token_urlsafe(24)


def write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def certificate(
    *,
    common_name: str,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    client: bool,
    ca: bool = False,
) -> x509.Certificate:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
    )
    if not ca:
        usage = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        if not client:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("signer"), x509.DNSName("localhost")]),
                critical=False,
            )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def generate_certificates() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if all((CERT_DIR / name).exists() for name in ("ca.pem", "signer.pem", "signer-key.pem")):
        return
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AegisLedger development CA")])
    ca_cert = certificate(
        common_name="AegisLedger development CA",
        issuer_name=ca_name,
        issuer_key=ca_key,
        public_key=ca_key.public_key(),
        client=False,
        ca=True,
    )
    write_private(
        CERT_DIR / "ca-key.pem",
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    (CERT_DIR / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    for name, client in (("signer", False), ("api-client", True)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cert = certificate(
            common_name=name,
            issuer_name=ca_cert.subject,
            issuer_key=ca_key,
            public_key=key.public_key(),
            client=client,
        )
        write_private(
            CERT_DIR / f"{name}-key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        (CERT_DIR / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def generate_signer_key() -> str:
    """Create the stable local-only wallet key consumed as a Compose secret."""
    SIGNER_SECRET_DIR.mkdir(parents=True, exist_ok=True)
    key_path = SIGNER_SECRET_DIR / "signer-private-key.hex"
    if not key_path.exists():
        write_private(key_path, ("0x" + secrets.token_hex(32) + "\n").encode())
    encoded = key_path.read_text(encoding="utf-8").strip().removeprefix("0x")
    private_value = int(encoded, 16)
    private_key = ec.derive_private_key(private_value, ec.SECP256K1())
    numbers = private_key.public_key().public_numbers()
    public_key = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    return "0x" + keccak(public_key[1:])[-20:].hex()


def generate_development_policy(signer_identity: str) -> None:
    DEVELOPMENT_POLICY_DIR.mkdir(parents=True, exist_ok=True)
    template = json.loads((ROOT / "configs" / "policy.dev.json").read_text(encoding="utf-8"))
    template["enabled_wallets"] = [signer_identity]
    (DEVELOPMENT_POLICY_DIR / "policy.dev.json").write_text(
        json.dumps(template, indent=2) + "\n",
        encoding="utf-8",
    )


def generate_environment(signer_identity: str) -> None:
    existing: dict[str, str] = {}
    if ENV_FILE.exists():
        existing = dict(
            line.split("=", 1)
            for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#") and "=" in line
        )
    seed = existing.get("AEGIS_POLICY_SIGNING_SEED", token())
    policy_keys = KeyPair.from_seed(f"policy-service::{seed}")
    policy = PolicyV1.model_validate_json(
        (DEVELOPMENT_POLICY_DIR / "policy.dev.json").read_text(encoding="utf-8")
    )
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to generate local runtime metadata")
    commit = subprocess.run(  # noqa: S603 - fixed command with no external input
        [git, "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    defaults = {
        "POSTGRES_USER": "aegisledger",
        "POSTGRES_PASSWORD": token(),
        "POSTGRES_DB": "aegisledger",
        "KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME": "local-admin",
        "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD": token(),
        "DEV_RESEARCHER_PASSWORD": token(),
        "DEV_POLICY_ADMIN_A_PASSWORD": token(),
        "DEV_POLICY_ADMIN_B_PASSWORD": token(),
        "DEV_AUDITOR_PASSWORD": token(),
        "GRAFANA_ADMIN_PASSWORD": token(),
        "AEGIS_POLICY_SIGNING_SEED": seed,
        "AEGIS_POLICY_PUBLIC_KEY_HEX": policy_keys.public_key_bytes().hex(),
        "AEGIS_ALLOWED_POLICY_HASHES": policy.policy_hash(),
        "AEGIS_COMMIT_SHA": commit,
        "AEGIS_SIGNER_IDENTITY": signer_identity,
        "AEGIS_ORGANIZATION_ID": "local",
        "AEGIS_DEPLOYMENT_ENVIRONMENT_ID": "development",
    }
    values = {
        **defaults,
        **existing,
        "AEGIS_POLICY_PUBLIC_KEY_HEX": policy_keys.public_key_bytes().hex(),
        "AEGIS_ALLOWED_POLICY_HASHES": policy.policy_hash(),
        "AEGIS_COMMIT_SHA": commit,
        "AEGIS_SIGNER_IDENTITY": signer_identity,
    }
    ENV_FILE.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    ENV_FILE.chmod(0o600)


def main() -> None:
    generate_certificates()
    signer_identity = generate_signer_key()
    generate_development_policy(signer_identity)
    generate_environment(signer_identity)
    print("Local credentials, signer key, and mTLS certificates are ready.")


if __name__ == "__main__":
    main()
