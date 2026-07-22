from __future__ import annotations

import html
import json

from .models import ScanResult


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    """Render findings as SARIF 2.1.0 for GitHub code scanning and CI systems."""
    findings = result.sorted_findings()
    rules = {}
    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
                "properties": {
                    "security-severity": str(
                        {
                            "critical": 9.5,
                            "high": 8.0,
                            "medium": 5.5,
                            "low": 3.0,
                            "info": 0.0,
                        }[finding.severity]
                    ),
                    "tags": ["security", "mcp", "ai-agent"],
                },
            },
        )

    results = []
    for finding in findings:
        message = f"{finding.message} JSON path: {finding.path}. Fix: {finding.remediation}"
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVELS[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.target},
                        },
                        "logicalLocations": [
                            {"name": finding.path, "kind": "configuration"}
                        ],
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "jsonPath": finding.path,
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Risk Lens",
                        "informationUri": "https://github.com/jicisala/mcp-risk-lens",
                        "semanticVersion": "0.1.0",
                        "rules": [rules[rule_id] for rule_id in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_text(result: ScanResult) -> str:
    lines = [
        f"MCP Risk Lens — {result.target}",
        f"Score: {result.score}/100 ({result.grade}) | Servers: {result.server_count} | Findings: {len(result.findings)}",
        "",
    ]
    if not result.findings:
        lines.append("No findings. Static analysis cannot prove that a configuration is safe.")
        return "\n".join(lines) + "\n"
    for finding in result.sorted_findings():
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                f"  Path: {finding.path}",
                f"  Why: {finding.message}",
                f"  Fix: {finding.remediation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_html(result: ScanResult) -> str:
    cards = []
    for finding in result.sorted_findings():
        evidence = ""
        if finding.evidence:
            evidence = f"<div class='evidence'><strong>Evidence:</strong> {html.escape(finding.evidence)}</div>"
        cards.append(
            f"""
            <article class="finding {finding.severity}">
              <header><span>{html.escape(finding.severity.upper())}</span> {html.escape(finding.rule_id)} · {html.escape(finding.title)}</header>
              <code>{html.escape(finding.path)}</code>
              <p>{html.escape(finding.message)}</p>
              {evidence}
              <div class="fix"><strong>Remediation:</strong> {html.escape(finding.remediation)}</div>
            </article>
            """
        )
    body = "".join(cards) or "<p class='empty'>No findings. Static analysis cannot prove that a configuration is safe.</p>"
    data = result.to_dict()
    counts = data["summary"]["counts"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCP Risk Lens Report</title>
  <style>
    :root {{ color-scheme: light; --ink:#14213d; --muted:#5f6b7a; --line:#dde3ea; --bg:#f5f7fa; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 ui-sans-serif,system-ui,-apple-system,sans-serif; }}
    main {{ max-width:960px; margin:0 auto; padding:48px 24px 72px; }}
    h1 {{ margin:0; font-size:34px; letter-spacing:-.03em; }}
    .sub {{ color:var(--muted); margin:6px 0 28px; }}
    .score {{ display:flex; gap:24px; align-items:center; background:white; border:1px solid var(--line); border-radius:16px; padding:22px; }}
    .grade {{ width:92px; height:92px; border-radius:50%; display:grid; place-items:center; background:#14213d; color:white; font-size:36px; font-weight:800; }}
    .metrics {{ display:grid; grid-template-columns:repeat(3,minmax(100px,1fr)); gap:12px; flex:1; }}
    .metric strong {{ display:block; font-size:24px; }} .metric span {{ color:var(--muted); }}
    h2 {{ margin:34px 0 14px; }}
    .finding {{ background:white; border:1px solid var(--line); border-left:6px solid #64748b; border-radius:12px; padding:18px 20px; margin:12px 0; }}
    .finding.critical {{ border-left-color:#9f1239; }} .finding.high {{ border-left-color:#dc2626; }}
    .finding.medium {{ border-left-color:#d97706; }} .finding.low {{ border-left-color:#2563eb; }}
    .finding header {{ font-weight:750; margin-bottom:8px; }}
    .finding header span {{ font-size:12px; letter-spacing:.08em; margin-right:6px; }}
    code {{ background:#eef2f7; border-radius:5px; padding:3px 6px; }}
    .fix,.evidence {{ background:#f8fafc; padding:10px 12px; border-radius:7px; margin-top:10px; }}
    footer {{ margin-top:32px; color:var(--muted); font-size:13px; }}
    @media(max-width:620px) {{ .score {{ align-items:flex-start; }} .metrics {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body><main>
  <h1>MCP Risk Lens</h1>
  <p class="sub">Offline static configuration review · {html.escape(result.target)} · {html.escape(result.scanned_at)}</p>
  <section class="score">
    <div class="grade">{result.grade}</div>
    <div class="metrics">
      <div class="metric"><strong>{result.score}</strong><span>Risk score / 100</span></div>
      <div class="metric"><strong>{result.server_count}</strong><span>MCP servers</span></div>
      <div class="metric"><strong>{len(result.findings)}</strong><span>Findings ({counts['critical']} critical, {counts['high']} high)</span></div>
    </div>
  </section>
  <h2>Findings</h2>
  {body}
  <footer>This report is heuristic static analysis, not a penetration test or compliance certification. The scanner never starts configured servers and makes no network calls.</footer>
</main></body></html>\n"""
