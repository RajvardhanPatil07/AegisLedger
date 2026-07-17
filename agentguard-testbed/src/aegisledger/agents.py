"""Provider-neutral model adapters constrained to the proposal-only boundary."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Annotated, Literal, Protocol

import httpx
from pydantic import StringConstraints, field_validator

from .contracts import Address, AssetId, ProposalV1, StrictModel


class ModelRequestV1(StrictModel):
    schema_version: Literal["aegisledger.model_request.v1"]
    request_id: Annotated[str, StringConstraints(min_length=8, max_length=128)]
    principal_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    wallet: Address
    chain_id: int
    allowed_assets: tuple[AssetId, ...]
    task: Annotated[str, StringConstraints(min_length=1, max_length=8_192)]
    context: dict[str, object]

    @field_validator("wallet")
    @classmethod
    def normalize_wallet(cls, value: str) -> str:
        return value.lower()

    @field_validator("allowed_assets", mode="before")
    @classmethod
    def accept_asset_array(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, (list, tuple)):
            raise TypeError("allowed_assets must be an array")
        return tuple(value)


class ModelProvider(Protocol):
    async def propose(self, request: ModelRequestV1) -> Mapping[str, object]: ...


class ScriptedModelProvider:
    """Deterministic baseline implementing the same interface as live providers."""

    def __init__(self, proposals: Sequence[Mapping[str, object]]) -> None:
        self._proposals = list(proposals)

    async def propose(self, request: ModelRequestV1) -> Mapping[str, object]:
        del request
        if not self._proposals:
            raise RuntimeError("scripted provider has no remaining proposals")
        return self._proposals.pop(0)


class JsonHttpModelProvider:
    """Provider-neutral JSON/HTTP live-model transport.

    The remote endpoint receives task context and returns ``{"proposal": ...}``.
    Output remains untrusted until ``ModelProposalAdapter`` validates it.
    """

    def __init__(self, client: httpx.AsyncClient, *, endpoint: str) -> None:
        if not endpoint.startswith("/"):
            raise ValueError("model endpoint must be an absolute path")
        self._client = client
        self._endpoint = endpoint

    async def propose(self, request: ModelRequestV1) -> Mapping[str, object]:
        response = await self._client.post(
            self._endpoint,
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or set(body) != {"proposal"}:
            raise ValueError("model response must contain only a proposal")
        proposal = body["proposal"]
        if not isinstance(proposal, dict):
            raise ValueError("model proposal must be an object")
        return proposal


class ModelProposalAdapter:
    def __init__(
        self,
        provider: ModelProvider,
        submit_proposal: Callable[[ProposalV1], object],
    ) -> None:
        self._provider = provider
        self._submit_proposal = submit_proposal

    async def execute(self, request: ModelRequestV1) -> ProposalV1:
        document = await self._provider.propose(request)
        proposal = ProposalV1.model_validate(document)
        if proposal.principal_id != request.principal_id:
            raise ValueError("model changed the authenticated principal")
        if proposal.wallet != request.wallet:
            raise ValueError("model changed the authorized wallet")
        if proposal.chain_id != request.chain_id:
            raise ValueError("model changed the authorized chain")
        if proposal.asset not in request.allowed_assets:
            raise ValueError("model selected an asset outside its request scope")
        self._submit_proposal(proposal)
        return proposal
