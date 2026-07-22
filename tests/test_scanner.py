from __future__ import annotations

import json

import pytest

from agentguard.scanner import ScanError, scan_config, scan_file


def rule_ids(result):
    return {finding.rule_id for finding in result.findings}


def test_detects_high_risk_configuration():
    config = {
        "mcpServers": {
            "filesystem-write": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                "env": {
                    "OPENAI_API_KEY": "sk-proj-exampleCredential123456",
                    "GITHUB_TOKEN": "${GITHUB_TOKEN}",
                },
            },
            "remote-admin": {
                "url": "http://mcp.example.test/api",
                "scopes": ["admin"],
            },
        }
    }

    result = scan_config(config)

    assert result.server_count == 2
    assert {"MRL001", "MRL003", "MRL004", "MRL005", "MRL006", "MRL007"} <= rule_ids(
        result
    )
    assert result.highest_severity == "critical"
    assert result.score < 60


def test_placeholders_and_local_http_are_not_credentials_or_transport_findings():
    config = {
        "mcpServers": {
            "local": {
                "url": "http://127.0.0.1:8080/mcp",
                "headers": {"Authorization": "${MCP_TOKEN}"},
            }
        }
    }

    result = scan_config(config)

    assert "MRL001" not in rule_ids(result)
    assert "MRL005" not in rule_ids(result)


def test_secret_metadata_boolean_is_not_treated_as_a_literal():
    config = {
        "mcpServers": {},
        "inputs": [{"id": "token", "password": True, "required": True}],
    }

    result = scan_config(config)

    assert "MRL001" not in rule_ids(result)


def test_nested_server_container_has_accurate_paths():
    config = {"mcp": {"servers": {"remote": {"url": "http://mcp.example.test"}}}}

    result = scan_config(config)

    finding = next(item for item in result.findings if item.rule_id == "MRL005")
    assert finding.path == "$.mcp.servers.remote.url"


def test_exact_package_version_is_not_flagged():
    config = {
        "mcpServers": {
            "files": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/srv/data"],
            }
        }
    }

    result = scan_config(config)

    assert "MRL003" not in rule_ids(result)
    assert "MRL004" not in rule_ids(result)


def test_explicit_approval_suppresses_approval_finding():
    config = {
        "policy": {"requireApproval": True},
        "mcpServers": {"payment-transfer": {"command": "payment-mcp"}},
    }

    result = scan_config(config)

    assert "MRL007" not in rule_ids(result)


def test_file_error_has_location(tmp_path):
    target = tmp_path / "broken.json"
    target.write_text('{"mcpServers":', encoding="utf-8")

    with pytest.raises(ScanError, match="line 1"):
        scan_file(target)


def test_result_json_is_stable_shape():
    result = scan_config({"mcpServers": {}}, target="sample.json")
    payload = result.to_dict()

    assert payload["schema_version"] == "1.0"
    assert payload["summary"]["grade"] == "A"
    assert payload["metadata"]["commands_executed"] is False
    json.dumps(payload)
