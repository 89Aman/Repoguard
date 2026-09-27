import json
import shutil
import subprocess
from pathlib import Path
from typing import List
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity


def _categorize_rule(rule_id: str, message: str) -> str:
    combined = f"{rule_id} {message}".lower()
    if any(k in combined for k in ("sql", "sqli", "b608")):
        return OWASPCategory.A03.value
    if any(k in combined for k in ("exec", "eval", "subprocess", "command", "b602", "b605", "b102")):
        return OWASPCategory.A03.value
    if any(k in combined for k in ("deserialize", "pickle", "yaml", "b301", "b506")):
        return OWASPCategory.A08.value
    if any(k in combined for k in ("traversal", "path", "file", "b108")):
        return OWASPCategory.A01.value
    if any(k in combined for k in ("md5", "sha1", "cipher", "crypto", "des", "b303", "b304", "b305")):
        return OWASPCategory.A02.value
    if any(k in combined for k in ("ssrf", "request", "urllib")):
        return OWASPCategory.A10.value
    if any(k in combined for k in ("password", "secret", "token", "b105", "b106", "b107")):
        return OWASPCategory.A07.value
    return OWASPCategory.A05.value


def run_bandit(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return findings

    root = Path(repo_path)
    cmd = [bandit_bin, "-r", str(root), "-f", "json", "-q", "-x", ".venv,venv,node_modules,repoguard-output,reports"]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = res.stdout.strip()
        if not output:
            return findings

        data = json.loads(output)
        results = data.get("results", [])

        for item in results:
            test_id = item.get("test_id", "BANDIT")
            test_name = item.get("test_name", "Security Issue")
            issue_text = item.get("issue_text", "")
            raw_severity = item.get("issue_severity", "MEDIUM").upper()
            code_snippet = item.get("code", "").strip()
            raw_file = item.get("filename", "")

            try:
                rel_file = str(Path(raw_file).relative_to(root)).replace("\\", "/")
            except Exception:
                rel_file = raw_file.replace("\\", "/")

            line_no = item.get("line_number", 1)
            owasp_cat = _categorize_rule(test_id, issue_text)

            sev_map = {
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = sev_map.get(raw_severity, Severity.MEDIUM)

            if test_id in ("B608", "B102", "B602", "B301") and severity == Severity.HIGH:
                severity = Severity.CRITICAL

            findings.append(
                Finding(
                    id=f"BANDIT-{test_id}-{line_no}",
                    title=f"Bandit: {test_name.replace('_', ' ').capitalize()} ({test_id})",
                    severity=severity,
                    owasp_category=owasp_cat,
                    source=FindingSource.SAST,
                    file_path=rel_file,
                    line_number=line_no,
                    description=issue_text,
                    offending_snippet=code_snippet,
                    fix=f"Review and sanitize input before executing {test_name}. Avoid string concatenation in queries or system commands.",
                )
            )
    except Exception:
        pass

    return findings


def run_semgrep(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return findings

    root = Path(repo_path)
    cmd = [
        semgrep_bin,
        "scan",
        "--config",
        "p/python",
        "--json",
        "--quiet",
        "--exclude",
        ".venv",
        "--exclude",
        "venv",
        "--exclude",
        "repoguard-output",
        str(root),
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = res.stdout.strip()
        if not output:
            return findings

        data = json.loads(output)
        results = data.get("results", [])

        for item in results:
            check_id = item.get("check_id", "SEMGREP")
            extra = item.get("extra", {})
            message = extra.get("message", "")
            raw_severity = extra.get("severity", "WARNING").upper()
            code_lines = extra.get("lines", "").strip()
            raw_path = item.get("path", "")

            try:
                rel_file = str(Path(raw_path).relative_to(root)).replace("\\", "/")
            except Exception:
                rel_file = raw_path.replace("\\", "/")

            start = item.get("start", {})
            line_no = start.get("line", 1)
            owasp_cat = _categorize_rule(check_id, message)

            sev_map = {
                "ERROR": Severity.HIGH,
                "WARNING": Severity.MEDIUM,
                "INFO": Severity.LOW,
            }
            severity = sev_map.get(raw_severity, Severity.MEDIUM)

            if any(k in check_id.lower() for k in ("sqli", "rce", "command-injection", "deserialization")):
                severity = Severity.CRITICAL

            findings.append(
                Finding(
                    id=f"SEMGREP-{check_id.split('.')[-1]}-{line_no}",
                    title=f"Semgrep: {check_id.split('.')[-1]}",
                    severity=severity,
                    owasp_category=owasp_cat,
                    source=FindingSource.SAST,
                    file_path=rel_file,
                    line_number=line_no,
                    description=message,
                    offending_snippet=code_lines,
                    fix="Follow secure coding guidelines for this pattern. Utilize parameterized APIs and validated input schemas.",
                )
            )
    except Exception:
        pass

    return findings


def scan_sast(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(run_bandit(repo_path))
    findings.extend(run_semgrep(repo_path))
    return findings
