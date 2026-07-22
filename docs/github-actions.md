# GitHub Actions integration

MCP Risk Lens can publish findings to the GitHub repository Security tab through SARIF 2.1.0.
The scanner remains offline: only the generated SARIF report is uploaded by GitHub Actions.

Save the following workflow as `.github/workflows/mcp-risk-lens.yml` and adjust the configuration
path if your project does not use `.vscode/mcp.json`.

```yaml
name: MCP Risk Lens

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install mcp-risk-lens
      - name: Scan MCP configuration
        run: >-
          mcp-risk-lens scan .vscode/mcp.json
          --format sarif
          --output mcp-risk-lens.sarif
          --fail-on never
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-risk-lens.sarif
      - name: Enforce high-severity gate
        run: mcp-risk-lens scan .vscode/mcp.json --fail-on high
```

## Safe operating guidance

- Keep real MCP configuration files private when they contain internal paths, endpoints, or policy
  details. The scanner redacts credential values, but repository visibility remains your decision.
- Prefer environment-variable references or a secret manager over literal credentials.
- Do not upload customer configurations or generated reports to a public issue.
- Pin the package version before using this workflow in a production release process.

