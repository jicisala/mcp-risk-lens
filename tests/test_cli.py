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

