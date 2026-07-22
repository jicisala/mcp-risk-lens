from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from .models import Finding


SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|bearer)"
)
PLACEHOLDER_RE = re.compile(
    r"^(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|<[^>]+>|YOUR_[A-Z0-9_]+|REDACTED|CHANGEME)$",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{12,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{12,}=*"),
    re.compile(r"(?i)(?:postgres|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@"),
)
DANGEROUS_SHELL_FLAGS = {"-c", "/c", "-command", "-encodedcommand"}
SHELL_COMMANDS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
DESTRUCTIVE_WORDS = {
    "delete",
    "drop",
    "destroy",
    "execute",
    "filesystem",
    "payment",
    "refund",
    "remove",
    "send-email",
    "shell",
    "sql-write",
    "transfer",
    "write",
}
SENSITIVE_ENV_NAMES = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return ""


def _walk(value: Any, path: str = "$") -> Iterator[tuple[str, str | None, Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            item_path = f"{path}.{key}"
            yield item_path, str(key), item
            yield from _walk(item, item_path)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            item_path = f"{path}[{index}]"
            yield item_path, None, item
            yield from _walk(item, item_path)


def find_secret_literals(config: Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, key, value in _walk(config):
        if not isinstance(value, str):
            continue
        text = _text(value).strip()
        if not text or PLACEHOLDER_RE.fullmatch(text):
            continue
        key_suggests_secret = bool(key and SECRET_KEY_RE.search(key))
        value_looks_secret = any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS)
        if not key_suggests_secret and not value_looks_secret:
            continue
        findings.append(
            Finding(
                rule_id="MRL001",
                title="Literal credential in configuration",
                severity="critical",
                path=path,
                message="A credential-like value is stored directly in the MCP configuration.",
                remediation="Load the value from a secret manager or environment variable and rotate it if exposed.",
                evidence="<redacted>",
            )
        )
    return findings


def find_shell_execution(server_name: str, server: Mapping[str, Any], base_path: str) -> list[Finding]:
    command = _text(server.get("command")).strip().lower()
    args = [_text(item).strip() for item in server.get("args", []) if _text(item).strip()]
    if command.rsplit("/", 1)[-1] not in SHELL_COMMANDS:
        return []
    if not any(arg.lower() in DANGEROUS_SHELL_FLAGS for arg in args):
        return []
    return [
        Finding(
            rule_id="MRL002",
            title="Shell interpreter executes an inline command",
            severity="high",
            path=f"{base_path}.command",
            message=f"Server '{server_name}' invokes a shell with an inline-command flag.",
            remediation="Invoke a fixed executable directly and pass validated arguments without a shell.",
            evidence=f"{command} {' '.join(args[:3])}".strip(),
        )
    ]


def find_unpinned_package(server_name: str, server: Mapping[str, Any], base_path: str) -> list[Finding]:
    command = _text(server.get("command")).strip().lower()
    args = [_text(item).strip() for item in server.get("args", []) if _text(item).strip()]
    package = next((arg for arg in args if not arg.startswith("-") and arg not in {"yes"}), "")
    if command not in {"npx", "uvx", "bunx"} or not package:
        return []
    normalized = package.rsplit("/", 1)[-1] if package.startswith("@") else package
    pinned = "@" in normalized or "==" in package
    if pinned:
        return []
    return [
        Finding(
            rule_id="MRL003",
            title="Package runner uses an unpinned dependency",
            severity="medium",
            path=f"{base_path}.args",
            message=f"Server '{server_name}' can download and execute a changing package version.",
            remediation="Pin an exact package version and review the publisher and lockfile before execution.",
            evidence=package,
        )
    ]


def find_broad_filesystem_scope(
    server_name: str, server: Mapping[str, Any], base_path: str
) -> list[Finding]:
    combined = " ".join(
        [server_name, _text(server.get("command"))]
        + [_text(item) for item in server.get("args", [])]
    ).lower()
    if "filesystem" not in combined and "file-system" not in combined:
        return []
    broad_values = {"/", "~", "$home", "${home}", "c:\\", "c:/"}
    args = [_text(item).strip().lower() for item in server.get("args", [])]
    broad = next((item for item in args if item in broad_values), None)
    if broad is None:
        return []
    return [
        Finding(
            rule_id="MRL004",
            title="Filesystem server has broad host access",
            severity="high",
            path=f"{base_path}.args",
            message=f"Server '{server_name}' appears able to access a filesystem root or home directory.",
            remediation="Restrict access to a dedicated project or data directory with least privilege.",
            evidence=broad,
        )
    ]


def find_insecure_transport(server_name: str, server: Mapping[str, Any], base_path: str) -> list[Finding]:
    url = _text(server.get("url")).strip()
    if not url.lower().startswith("http://"):
        return []
    if re.match(r"^http://(?:localhost|127\.0\.0\.1|\[::1\])(?::|/|$)", url, re.I):
        return []
    return [
        Finding(
            rule_id="MRL005",
            title="Remote MCP transport is not encrypted",
            severity="high",
            path=f"{base_path}.url",
            message=f"Server '{server_name}' uses cleartext HTTP for a non-local endpoint.",
            remediation="Use HTTPS with certificate validation; prefer mTLS for sensitive enterprise tools.",
            evidence=url,
        )
    ]


def find_excessive_scope(server_name: str, server: Mapping[str, Any], base_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, key, value in _walk(server, base_path):
        if not key or key.lower() not in {"scope", "scopes", "permissions"}:
            continue
        values = value if isinstance(value, list) else [value]
        risky = [str(item) for item in values if str(item).lower() in {"*", "admin", "repo", "all"}]
        if risky:
            findings.append(
                Finding(
                    rule_id="MRL006",
                    title="Broad authorization scope",
                    severity="high",
                    path=path,
                    message=f"Server '{server_name}' requests a broad authorization scope.",
                    remediation="Replace broad scopes with the minimum read/write permissions required.",
                    evidence=", ".join(risky),
                )
            )
    return findings


def find_destructive_without_approval(
    server_name: str, server: Mapping[str, Any], base_path: str, root: Mapping[str, Any]
) -> list[Finding]:
    combined = " ".join(
        [server_name, _text(server.get("command")), _text(server.get("description"))]
        + [_text(item) for item in server.get("args", [])]
    ).lower()
    if not any(word in combined for word in DESTRUCTIVE_WORDS):
        return []
    approval_keys = {"approval", "humanapproval", "requireapproval", "confirmation"}
    has_approval = any(
        key and key.replace("_", "").lower() in approval_keys and bool(value)
        for _, key, value in _walk(root)
    )
    if has_approval:
        return []
    return [
        Finding(
            rule_id="MRL007",
            title="Risky capability lacks an explicit approval policy",
            severity="medium",
            path=base_path,
            message=f"Server '{server_name}' appears capable of sensitive or destructive actions.",
            remediation="Require human approval for irreversible writes and define an auditable allowlist.",
            evidence=server_name,
            confidence="medium",
        )
    ]


def find_sensitive_env_forwarding(
    server_name: str, server: Mapping[str, Any], base_path: str
) -> list[Finding]:
    env = server.get("env")
    if not isinstance(env, Mapping):
        return []
    names = sorted(name for name in env if str(name).upper() in SENSITIVE_ENV_NAMES)
    if len(names) < 3:
        return []
    return [
        Finding(
            rule_id="MRL008",
            title="Multiple sensitive credentials forwarded to one server",
            severity="medium",
            path=f"{base_path}.env",
            message=f"Server '{server_name}' receives several high-value credentials, increasing blast radius.",
            remediation="Split capabilities across servers and provide each server only the credential it needs.",
            evidence=", ".join(names),
        )
    ]


def run_rules(
    config: Mapping[str, Any], servers: Mapping[str, Any], server_container_path: str
) -> list[Finding]:
    findings = find_secret_literals(config)
    for name, raw_server in servers.items():
        if not isinstance(raw_server, Mapping):
            continue
        base_path = f"{server_container_path}.{name}"
        findings.extend(find_shell_execution(str(name), raw_server, base_path))
        findings.extend(find_unpinned_package(str(name), raw_server, base_path))
        findings.extend(find_broad_filesystem_scope(str(name), raw_server, base_path))
        findings.extend(find_insecure_transport(str(name), raw_server, base_path))
        findings.extend(find_excessive_scope(str(name), raw_server, base_path))
        findings.extend(find_destructive_without_approval(str(name), raw_server, base_path, config))
        findings.extend(find_sensitive_env_forwarding(str(name), raw_server, base_path))
    return findings
