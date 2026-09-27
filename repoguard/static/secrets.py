import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity

FALLBACK_PATTERNS = [
    ("AWS Access Key", r"(?i)\b(AKIA[0-9A-Z]{16})\b", Severity.CRITICAL),
    ("GitHub Personal Access Token", r"\b(ghp_[a-zA-Z0-9]{36})\b", Severity.CRITICAL),
    ("Slack API Token", r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b", Severity.CRITICAL),
    ("Stripe API Secret", r"\b(sk_live_[0-9a-zA-Z]{24,99})\b", Severity.CRITICAL),
    ("Generic Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("Generic Bearer Secret", r'(?i)(?:api_key|apikey|secret_key|auth_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', Severity.HIGH),
]

EXCLUDE_DIRS = {".git", ".venv", "venv", "node_modules", "repoguard-output", "reports"}


def _run_gitleaks(repo_path: Path, gitleaks_bin: str) -> List[Finding]:
    findings: List[Finding] = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_file = tmp.name

    try:
        is_git = (repo_path / ".git").exists()
        cmd = [gitleaks_bin, "git" if is_git else "dir", "--source", str(repo_path), "--report-format", "json", "--report-path", report_file]
        subprocess.run(cmd, capture_output=True, text=True, check=False)

        if os.path.exists(report_file) and os.path.getsize(report_file) > 0:
            with open(report_file, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    rule_id = item.get("RuleID", "Secret")
                    desc = item.get("Description", "Detected secret in source code")
                    secret_val = item.get("Secret", "")
                    raw_file = item.get("File", "")
                    line_no = item.get("StartLine", 1)

                    try:
                        rel_file = str(Path(raw_file).relative_to(repo_path)).replace("\\", "/")
                    except Exception:
                        rel_file = raw_file.replace("\\", "/")

                    masked = secret_val[:3] + ("*" * max(0, len(secret_val) - 6)) + secret_val[-3:] if len(secret_val) > 6 else "***"

                    findings.append(
                        Finding(
                            id=f"LEAK-{rule_id}-{line_no}",
                            title=f"Hardcoded secret detected: {desc}",
                            severity=Severity.CRITICAL,
                            owasp_category=OWASPCategory.A07.value,
                            source=FindingSource.SECRETS,
                            file_path=rel_file,
                            line_number=line_no,
                            description=f"Secret rule '{rule_id}' matched: {desc}. Exposed credential in code.",
                            offending_snippet=f"Secret: {masked}",
                            fix="Remove secret from repository immediately, rotate credential across all services, and inject via environment variables.",
                        )
                    )
    except Exception:
        pass
    finally:
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except OSError:
                pass

    return findings


def _scan_regex_fallback(repo_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        parts = p.relative_to(repo_path).parts
        if any(ignored in parts for ignored in EXCLUDE_DIRS):
            continue

        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue

        rel_path = str(p.relative_to(repo_path)).replace("\\", "/")
        for line_idx, line in enumerate(lines, start=1):
            for name, pattern, severity in FALLBACK_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    raw_val = match.group(0)
                    masked = raw_val[:4] + ("*" * max(0, len(raw_val) - 8)) + raw_val[-4:] if len(raw_val) > 8 else "***"
                    findings.append(
                        Finding(
                            id=f"SECRET-{name.replace(' ', '-')}-{line_idx}",
                            title=f"Hardcoded credential: {name}",
                            severity=severity,
                            owasp_category=OWASPCategory.A07.value,
                            source=FindingSource.SECRETS,
                            file_path=rel_path,
                            line_number=line_idx,
                            description=f"Potential {name} pattern discovered in file '{rel_path}'.",
                            offending_snippet=f"Snippet: {masked}",
                            fix="Revoke and rotate exposed credential immediately. Utilize environment variables or vault storage.",
                        )
                    )
    return findings


def scan_secrets(repo_path: str) -> List[Finding]:
    root = Path(repo_path)
    gitleaks_bin = shutil.which("gitleaks")

    if gitleaks_bin:
        findings = _run_gitleaks(root, gitleaks_bin)
        if findings:
            return findings

    return _scan_regex_fallback(root)
