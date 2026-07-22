from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_ORDER
from .report import render_html, render_json, render_sarif, render_text
from .scanner import ScanError, scan_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-risk-lens",
        description="Offline static risk scanner for MCP JSON configurations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan an MCP configuration file")
    scan.add_argument("path", help="Path to a JSON MCP configuration")
    scan.add_argument("--format", choices=("text", "json", "html", "sarif"), default="text")
    scan.add_argument("--output", "-o", help="Write the report to this file")
    scan.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "never"),
        default="critical",
        help="Return exit code 1 when this severity or higher is found (default: critical)",
    )
    return parser


def _should_fail(highest: str, threshold: str) -> bool:
    if threshold == "never" or highest == "none":
        return False
    return SEVERITY_ORDER[highest] >= SEVERITY_ORDER[threshold]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan_file(args.path)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    renderer = {
        "text": render_text,
        "json": render_json,
        "html": render_html,
        "sarif": render_sarif,
    }[args.format]
    output = renderer(result)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output, end="")
    return 1 if _should_fail(result.highest_severity, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
