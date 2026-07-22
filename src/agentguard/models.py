from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_PENALTY = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    message: str
    remediation: str
    evidence: str | None = None
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    server_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_PENALTY.get(item.severity, 0) for item in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        if self.score >= 90:
            return "A"
        if self.score >= 80:
            return "B"
        if self.score >= 70:
            return "C"
        if self.score >= 60:
            return "D"
        return "F"

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (-SEVERITY_ORDER[item.severity], item.rule_id, item.path),
        )

    def to_dict(self) -> dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "schema_version": "1.0",
            "tool": {"name": "mcp-risk-lens", "version": "0.1.0"},
            "target": self.target,
            "scanned_at": self.scanned_at,
            "summary": {
                "score": self.score,
                "grade": self.grade,
                "highest_severity": self.highest_severity,
                "server_count": self.server_count,
                "finding_count": len(self.findings),
                "counts": counts,
            },
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
        }


def display_target(path: Path | str) -> str:
    value = str(path)
    try:
        return str(Path(value).resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return value

