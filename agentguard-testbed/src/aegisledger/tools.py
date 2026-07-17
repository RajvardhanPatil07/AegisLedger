"""Versioned MCP adapters with definition pinning and argument-level DLP."""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Annotated, Literal, Protocol, cast

from pydantic import StringConstraints, field_validator

from .canonical import canonical_json
from .contracts import StrictModel


class Provenance(StrEnum):
    TRUSTED_LOCAL = "TRUSTED_LOCAL"
    VERIFIED_REMOTE = "VERIFIED_REMOTE"
    UNTRUSTED_REMOTE = "UNTRUSTED_REMOTE"


class McpToolDefinitionV1(StrictModel):
    schema_version: Literal["aegisledger.mcp_tool.v1"]
    name: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{1,95}$")]
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    description: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    input_schema: dict[str, object]
    provenance: Provenance

    @field_validator("provenance", mode="before")
    @classmethod
    def parse_provenance(cls, value: object) -> Provenance:
        if isinstance(value, Provenance):
            return value
        if isinstance(value, str):
            return Provenance(value)
        raise TypeError("provenance must be a named provenance label")

    @field_validator("input_schema")
    @classmethod
    def require_closed_object_schema(cls, schema: dict[str, object]) -> dict[str, object]:
        if schema.get("type") != "object":
            raise ValueError("tool input schema must describe an object")
        if schema.get("additionalProperties") is not False:
            raise ValueError("tool input schema must forbid additional properties")
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            raise ValueError("tool input schema requires properties")
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            raise ValueError("tool required fields must be a string array")
        if not set(required).issubset(properties):
            raise ValueError("required tool fields must be declared properties")
        return schema

    def definition_hash(self) -> str:
        import hashlib

        return "0x" + hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()


class McpToolResultV1(StrictModel):
    schema_version: Literal["aegisledger.mcp_result.v1"] = "aegisledger.mcp_result.v1"
    tool_name: str
    definition_hash: str
    provenance: Provenance
    value: object


class McpServer(Protocol):
    def list_tools(self) -> tuple[McpToolDefinitionV1, ...]: ...

    def call_tool(self, name: str, arguments: Mapping[str, object]) -> object: ...


class InProcessMcpServer:
    """Local adapter implementing the same boundary as a remote MCP transport."""

    def __init__(
        self,
        tools: Mapping[str, tuple[McpToolDefinitionV1, Callable[..., object]]],
    ) -> None:
        self._tools = dict(tools)

    def list_tools(self) -> tuple[McpToolDefinitionV1, ...]:
        return tuple(item[0] for item in self._tools.values())

    def call_tool(self, name: str, arguments: Mapping[str, object]) -> object:
        try:
            definition, handler = self._tools[name]
        except KeyError as exc:
            raise LookupError("unknown MCP tool") from exc
        del definition
        return handler(**dict(arguments))


class ToolCallDenied(PermissionError):
    """Fail-closed rejection raised before an untrusted tool is invoked."""


class ToolSandbox:
    _SENSITIVE_KEY = re.compile(
        r"(?:api.?key|credential|password|private.?key|rpc.?key|secret|session|sidenote|token)",
        re.IGNORECASE,
    )
    _SENSITIVE_VALUE = re.compile(
        r"(?:WALLET_CONFIG|api[_-]?key\s*[=:]|private[_ -]?key|rpc[_-]?key\s*[=:]|"
        r"session\s*[=:]|sk-(?:live|test)-|token\s*[=:])",
        re.IGNORECASE,
    )

    def __init__(
        self,
        *,
        pinned_definitions: Mapping[str, str] | None = None,
        dlp_enabled: bool = True,
    ) -> None:
        self._pins = dict(pinned_definitions or {})
        self._dlp_enabled = dlp_enabled

    def invoke(
        self,
        server: McpServer,
        tool_name: str,
        arguments: Mapping[str, object],
    ) -> McpToolResultV1:
        definitions = {definition.name: definition for definition in server.list_tools()}
        definition = definitions.get(tool_name)
        if definition is None:
            raise ToolCallDenied("tool is not declared by the MCP server")
        definition_hash = definition.definition_hash()
        expected_hash = self._pins.get(tool_name)
        if expected_hash is not None and expected_hash != definition_hash:
            raise ToolCallDenied("tool definition changed after approval")

        self._validate_arguments(definition, arguments)
        result = server.call_tool(tool_name, arguments)
        return McpToolResultV1(
            tool_name=tool_name,
            definition_hash=definition_hash,
            provenance=definition.provenance,
            value=result,
        )

    def _validate_arguments(
        self,
        definition: McpToolDefinitionV1,
        arguments: Mapping[str, object],
    ) -> None:
        schema = definition.input_schema
        properties = schema["properties"]
        assert isinstance(properties, dict)
        required_value = schema.get("required", [])
        assert isinstance(required_value, list)
        required = set(cast(list[str], required_value))
        supplied = set(arguments)
        missing = required - supplied
        if missing:
            raise ToolCallDenied(f"required tool arguments missing: {sorted(missing)}")
        undeclared = supplied - set(properties)
        if undeclared:
            raise ToolCallDenied(f"undeclared tool arguments: {sorted(undeclared)}")

        for key, value in arguments.items():
            field_schema = properties[key]
            if not isinstance(field_schema, dict):
                raise ToolCallDenied("invalid tool field schema")
            self._require_json_type(key, value, field_schema.get("type"))
            if self._dlp_enabled:
                self._scan_sensitive(key, value)

    @staticmethod
    def _require_json_type(key: str, value: object, expected: object) -> None:
        expected_types: dict[str, type[object] | tuple[type[object], ...]] = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        if not isinstance(expected, str):
            raise ToolCallDenied(f"unsupported schema type for argument {key}")
        python_type = expected_types.get(expected)
        if python_type is None:
            raise ToolCallDenied(f"unsupported schema type for argument {key}")
        if isinstance(value, bool) and expected in {"integer", "number"}:
            raise ToolCallDenied(f"argument {key} has the wrong type")
        if not isinstance(value, python_type):
            raise ToolCallDenied(f"argument {key} has the wrong type")

    def _scan_sensitive(self, key: str, value: object) -> None:
        if self._SENSITIVE_KEY.search(key):
            raise ToolCallDenied(f"sensitive argument name rejected: {key}")
        if isinstance(value, str):
            if self._SENSITIVE_VALUE.search(value) or self._looks_like_high_entropy_secret(value):
                raise ToolCallDenied(f"sensitive material rejected in argument {key}")
        elif isinstance(value, dict):
            for nested_key, nested_value in value.items():
                self._scan_sensitive(str(nested_key), nested_value)
        elif isinstance(value, list):
            for nested_value in value:
                self._scan_sensitive(key, nested_value)

    @staticmethod
    def _looks_like_high_entropy_secret(value: str) -> bool:
        compact = "".join(value.split())
        if len(compact) < 32 or compact.startswith("0x"):
            return False
        counts = {character: compact.count(character) for character in set(compact)}
        entropy = -sum(
            (count / len(compact)) * math.log2(count / len(compact)) for count in counts.values()
        )
        return entropy >= 4.5
