"""mTLS gRPC client for the isolated signer boundary."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import grpc  # type: ignore[import-untyped]
from eth_hash.auto import keccak
from google.protobuf import (  # type: ignore[import-untyped]
    descriptor_pb2,
    descriptor_pool,
    message_factory,
)

from .signing import TransactionSignRequestV1


class SignerClientError(RuntimeError):
    """A fail-closed signer transport or response-validation failure."""


@dataclass(frozen=True, slots=True)
class SignerIdentity:
    signer_identity: str
    secp256k1_public_key: str
    build_measurement: str


@dataclass(frozen=True, slots=True)
class SignerResult:
    signing_hash: str
    transaction_hash: str
    signed_transaction: bytes
    wallet_nonce: int
    chain_id: int
    decision_id: uuid.UUID
    signer_identity: str
    signature: str
    enclave_evidence: dict[str, object]


class Signer(Protocol):
    def identity(self) -> SignerIdentity: ...

    def sign(self, request: TransactionSignRequestV1) -> SignerResult: ...


def _add_field(message: Any, name: str, number: int, field_type: int) -> None:
    field = message.field.add()
    field.name = name
    field.number = number
    field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    field.type = field_type


def _message_classes() -> dict[str, Any]:
    file_descriptor = descriptor_pb2.FileDescriptorProto(
        name="signer.proto",
        package="aegisledger.signer.v1",
        syntax="proto3",
    )
    request = file_descriptor.message_type.add()
    request.name = "SignAuthorizedTransactionRequest"
    _add_field(request, "authorization_json", 1, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES)

    response = file_descriptor.message_type.add()
    response.name = "SignAuthorizedTransactionResponse"
    for name, number, field_type in (
        ("eip1559_hash", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING),
        ("wallet_nonce", 2, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64),
        ("chain_id", 3, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64),
        ("decision_id", 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING),
        ("signer_identity", 5, descriptor_pb2.FieldDescriptorProto.TYPE_STRING),
        ("signature", 6, descriptor_pb2.FieldDescriptorProto.TYPE_STRING),
        ("enclave_evidence_json", 7, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES),
        ("signed_transaction", 8, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES),
        ("transaction_hash", 9, descriptor_pb2.FieldDescriptorProto.TYPE_STRING),
        ("signing_hash", 10, descriptor_pb2.FieldDescriptorProto.TYPE_STRING),
    ):
        _add_field(response, name, number, field_type)

    identity_request = file_descriptor.message_type.add()
    identity_request.name = "PublicIdentityRequest"
    identity_response = file_descriptor.message_type.add()
    identity_response.name = "PublicIdentityResponse"
    _add_field(
        identity_response,
        "signer_identity",
        1,
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
    )
    _add_field(
        identity_response,
        "secp256k1_public_key",
        2,
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
    )
    _add_field(
        identity_response,
        "build_measurement",
        3,
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
    )

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_descriptor)
    return {
        name: message_factory.GetMessageClass(
            pool.FindMessageTypeByName(f"aegisledger.signer.v1.{name}")
        )
        for name in (
            "SignAuthorizedTransactionRequest",
            "SignAuthorizedTransactionResponse",
            "PublicIdentityRequest",
            "PublicIdentityResponse",
        )
    }


_MESSAGES = _message_classes()
Rpc = Callable[[Any, float], Any]


class GrpcSignerClient:
    """Signer adapter that treats every server field as untrusted input."""

    def __init__(
        self,
        target: str,
        *,
        root_ca: Path | None = None,
        client_certificate: Path | None = None,
        client_private_key: Path | None = None,
        timeout_seconds: float = 5.0,
        sign_rpc: Rpc | None = None,
        identity_rpc: Rpc | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("signer timeout must be positive")
        self._timeout = timeout_seconds
        self._channel: grpc.Channel | None = None
        if sign_rpc is not None and identity_rpc is not None:
            self._sign_rpc = sign_rpc
            self._identity_rpc = identity_rpc
            return
        if sign_rpc is not None or identity_rpc is not None:
            raise ValueError("both test RPC callables must be provided together")
        if not target or "://" in target:
            raise ValueError("signer target must use host:port form")
        if root_ca is None or client_certificate is None or client_private_key is None:
            raise ValueError("signer mTLS CA, certificate, and private key are required")
        credentials = grpc.ssl_channel_credentials(
            root_certificates=root_ca.read_bytes(),
            private_key=client_private_key.read_bytes(),
            certificate_chain=client_certificate.read_bytes(),
        )
        self._channel = grpc.secure_channel(target, credentials)
        self._sign_rpc = self._channel.unary_unary(
            "/aegisledger.signer.v1.IsolatedSigner/SignAuthorizedTransaction",
            request_serializer=lambda message: message.SerializeToString(),
            response_deserializer=_MESSAGES["SignAuthorizedTransactionResponse"].FromString,
        )
        self._identity_rpc = self._channel.unary_unary(
            "/aegisledger.signer.v1.IsolatedSigner/PublicIdentity",
            request_serializer=lambda message: message.SerializeToString(),
            response_deserializer=_MESSAGES["PublicIdentityResponse"].FromString,
        )

    def identity(self) -> SignerIdentity:
        try:
            response = self._identity_rpc(
                _MESSAGES["PublicIdentityRequest"](),
                self._timeout,
            )
        except grpc.RpcError as error:
            raise SignerClientError("isolated signer identity request failed") from error
        identity = str(response.signer_identity).lower()
        public_key = str(response.secp256k1_public_key).lower()
        measurement = str(response.build_measurement)
        if (
            not identity.startswith("0x")
            or len(identity) != 42
            or not public_key.startswith("0x04")
            or len(public_key) != 132
            or not measurement
        ):
            raise SignerClientError("isolated signer returned an invalid identity")
        return SignerIdentity(identity, public_key, measurement)

    def sign(self, request: TransactionSignRequestV1) -> SignerResult:
        wire_request = _MESSAGES["SignAuthorizedTransactionRequest"](
            authorization_json=request.model_dump_json().encode()
        )
        try:
            response = self._sign_rpc(wire_request, self._timeout)
        except grpc.RpcError as error:
            raise SignerClientError("isolated signer denied or failed the request") from error
        return self._validated_result(request, response)

    @staticmethod
    def _validated_result(request: TransactionSignRequestV1, response: Any) -> SignerResult:
        signing_hash = str(response.signing_hash).lower()
        transaction_hash = str(response.transaction_hash).lower()
        raw_transaction = bytes(response.signed_transaction)
        signer_identity = str(response.signer_identity).lower()
        signature = str(response.signature).lower()
        if (
            signing_hash != request.eip1559_hash
            or str(response.eip1559_hash).lower() != signing_hash
            or int(response.wallet_nonce) != request.wallet_nonce
            or int(response.chain_id) != request.chain_id
            or str(response.decision_id) != str(request.decision.decision_id)
        ):
            raise SignerClientError("isolated signer response does not match the request")
        if not raw_transaction.startswith(b"\x02"):
            raise SignerClientError("isolated signer omitted a signed type-2 transaction")
        computed_hash = "0x" + keccak(raw_transaction).hex()
        if transaction_hash != computed_hash:
            raise SignerClientError("isolated signer transaction hash does not match raw bytes")
        if (
            not signer_identity.startswith("0x")
            or len(signer_identity) != 42
            or not signature.startswith("0x")
            or len(signature) != 132
        ):
            raise SignerClientError("isolated signer signature metadata is malformed")
        try:
            evidence = json.loads(bytes(response.enclave_evidence_json))
        except (TypeError, ValueError) as error:
            raise SignerClientError("isolated signer evidence is invalid JSON") from error
        if not isinstance(evidence, dict):
            raise SignerClientError("isolated signer evidence must be an object")
        if (
            str(evidence.get("transaction_hash", "")).lower() != transaction_hash
            or str(evidence.get("signing_hash", "")).lower() != signing_hash
            or str(evidence.get("decision_id", "")) != str(request.decision.decision_id)
            or str(evidence.get("signer_identity", "")).lower() != signer_identity
        ):
            raise SignerClientError("isolated signer evidence does not match its response")
        return SignerResult(
            signing_hash=signing_hash,
            transaction_hash=transaction_hash,
            signed_transaction=raw_transaction,
            wallet_nonce=request.wallet_nonce,
            chain_id=request.chain_id,
            decision_id=request.decision.decision_id,
            signer_identity=signer_identity,
            signature=signature,
            enclave_evidence=evidence,
        )

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
