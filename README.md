# MCP Risk Lens

Offline, deterministic static risk review for MCP configuration files.

[简体中文](README.zh-CN.md) · [Professional review](docs/professional-review.md)

MCP Risk Lens helps engineering and security teams catch dangerous defaults before an AI agent
starts a tool server. It does **not** execute configured commands, start MCP servers, upload files,
or make network calls.

> Status: early public MVP. The scanner is intentionally narrow and its findings are heuristics,
> not a penetration test or compliance certification.

## Why this project

MCP configurations can quietly combine package execution, filesystem access, remote endpoints,
and production credentials. Reviewing each field manually is slow and inconsistent. MCP Risk Lens
turns those checks into a repeatable local report that can also run in CI.

## Checks in v0.1

| Rule | Risk |
|---|---|
| `MRL001` | Literal credentials and credential-bearing URLs |
| `MRL002` | Shell interpreters executing inline commands |
| `MRL003` | Unpinned packages executed through `npx`, `uvx`, or `bunx` |
| `MRL004` | Filesystem servers scoped to root or a home directory |
| `MRL005` | Cleartext remote HTTP transports |
| `MRL006` | Broad scopes such as `admin`, `repo`, or `*` |
| `MRL007` | Sensitive capabilities without an explicit approval policy |
| `MRL008` | Excessive credential concentration in one server |

## Quick start

```bash
python -m pip install -e .
mcp-risk-lens scan examples/insecure.mcp.json
```

Create a standalone HTML report:

```bash
mcp-risk-lens scan examples/insecure.mcp.json \
  --format html \
  --output reports/mcp-risk-report.html \
  --fail-on never
```

CI-friendly JSON and severity gates:

```bash
mcp-risk-lens scan .vscode/mcp.json --format json --output report.json --fail-on high
```

Generate SARIF 2.1.0 for GitHub code scanning or another compatible CI system:

```bash
mcp-risk-lens scan .vscode/mcp.json \
  --format sarif \
  --output mcp-risk-lens.sarif \
  --fail-on never
```

See the [GitHub Actions integration guide](docs/github-actions.md) for a complete workflow that
uploads results to the repository Security tab.

Exit codes:

- `0`: scan completed and the severity threshold was not reached
- `1`: a finding met or exceeded `--fail-on`
- `2`: input or usage error

## Supported input

The MVP accepts UTF-8 JSON with servers stored under `mcpServers`, `servers`,
`mcp.mcpServers`, or `mcp.servers`. It is compatible with common Claude Desktop, Cursor, VS Code,
and custom MCP configuration shapes that use these containers.

## Safety properties

- Offline by design: no telemetry and no API token.
- Static only: configured commands are treated as text and never executed.
- Secret-safe reports: detected credential values are always replaced with `<redacted>`.
- Deterministic: the same configuration and rule version produce the same ordered findings.

Run scanners on a copy of sensitive configuration and keep generated reports private unless they
contain only synthetic data.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check src tests
pytest -q
```

## What comes next

- YAML and directory discovery
- Policy-as-code profiles for read-only, developer, and production environments
- Diff mode to block newly introduced risk
- Evidence-backed enterprise review templates

## Professional review

The open-source scanner is a starting point. A professional MCP and AI Agent governance review can
add architecture-level threat modeling, tool authorization design, approval flows, observability,
and a prioritized remediation plan. See the [professional review options](docs/professional-review.md).

Never post credentials, proprietary configurations, customer data, or non-public architecture in a
GitHub issue. Initial inquiries should contain public, high-level information only.

## License

Apache-2.0
