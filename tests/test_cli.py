from __future__ import annotations

import json

from agentguard.cli import main


def test_cli_writes_html_report(tmp_path):
    config = tmp_path / "mcp.json"
    report = tmp_path / "report.html"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "http://mcp.example.test", "scopes": ["admin"]}
                }
            }
        ),
        encoding="utf-8",
    )

    code = main(["scan", str(config), "--format", "html", "--output", str(report)])

    assert code == 0
    assert "MCP Risk Lens" in report.read_text(encoding="utf-8")


def test_cli_fail_threshold(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"files": {"command": "bash", "args": ["-c", "echo ok"]}}}),
        encoding="utf-8",
    )

    assert main(["scan", str(config), "--fail-on", "high"]) == 1
    assert main(["scan", str(config), "--fail-on", "critical"]) == 0


def test_cli_writes_github_compatible_sarif(tmp_path):
    config = tmp_path / "mcp.json"
    report = tmp_path / "mcp-risk-lens.sarif"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "http://mcp.example.test", "scopes": ["admin"]}
                }
            }
        ),
        encoding="utf-8",
    )

    code = main(
        [
            "scan",
            str(config),
            "--format",
            "sarif",
            "--output",
            str(report),
            "--fail-on",
            "never",
        ]
    )
    payload = json.loads(report.read_text(encoding="utf-8"))

    assert code == 0
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "MCP Risk Lens"
    assert {item["ruleId"] for item in payload["runs"][0]["results"]} == {
        "MRL005",
        "MRL006",
    }
    assert payload["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0][
        "kind"
    ] == "configuration"
