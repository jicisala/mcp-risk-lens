from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import ScanResult, display_target
from .rules import run_rules


class ScanError(ValueError):
    """Raised when an input cannot be parsed as a supported MCP configuration."""


def _extract_servers(config: Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
    for key in ("mcpServers", "servers"):
        value = config.get(key)
        if isinstance(value, Mapping):
            return value, f"$.{key}"
    nested = config.get("mcp")
    if isinstance(nested, Mapping):
        for key in ("mcpServers", "servers"):
            value = nested.get(key)
            if isinstance(value, Mapping):
                return value, f"$.mcp.{key}"
    return {}, "$.mcpServers"


def scan_config(config: Mapping[str, Any], target: str = "<memory>") -> ScanResult:
    if not isinstance(config, Mapping):
        raise ScanError("The root value must be a JSON object.")
    servers, server_container_path = _extract_servers(config)
    result = ScanResult(target=target, server_count=len(servers))
    result.metadata = {
        "mode": "static",
        "network_calls": False,
        "commands_executed": False,
        "server_container": "detected" if servers else "not_detected",
    }
    result.findings.extend(run_rules(config, servers, server_container_path))
    return result


def scan_file(path: str | Path) -> ScanResult:
    source = Path(path)
    if not source.is_file():
        raise ScanError(f"Input file does not exist: {source}")
    try:
        config = json.loads(source.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise ScanError(f"Input is not valid UTF-8: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ScanError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    return scan_config(config, display_target(source))
