import json
import shutil
import subprocess
from pathlib import Path
from typing import List
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity


def _find_dependency_files(repo_path: Path) -> List[tuple]:
    files = []
    for p in repo_path.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(repo_path)).replace("\\", "/")
        if any(ignored in rel for ignored in (".venv", "venv", "node_modules", ".git")):
            continue

        name = p.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            files.append(("req", p))
        elif name == "poetry.lock":
            files.append(("poetry", p))
        elif name == "pipfile.lock":
            files.append(("pipfile", p))
    return files


def scan_dependencies(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    root = Path(repo_path)
    dep_files = _find_dependency_files(root)

    if not dep_files:
        return findings

    pip_audit_bin = shutil.which("pip-audit")
    if not pip_audit_bin:
        findings.append(
            Finding(
                id="DEP-PIP-AUDIT-MISSING",
                title="pip-audit scanner not found in PATH",
                severity=Severity.INFO,
                owasp_category=OWASPCategory.A06.value,
                source=FindingSource.DEPENDENCIES,
                file_path=str(dep_files[0][1].relative_to(root)),
                line_number=1,
                description="pip-audit binary is not installed in current environment. Dependency CVE assessment could not run.",
                offending_snippet="",
                fix="Install pip-audit with 'pip install pip-audit' or run via RepoGuard Docker container.",
            )
        )
        return findings

    for file_type, file_path in dep_files:
        cmd = [pip_audit_bin, "-f", "json"]
        if file_type == "req":
            cmd.extend(["-r", str(file_path)])
        else:
            cmd.extend(["-l", str(file_path)])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = res.stdout.strip()
            if not output and res.stderr:
                continue

            data = json.loads(output)
            deps = data.get("dependencies", [])

            for dep in deps:
                name = dep.get("name")
                version = dep.get("version")
                vulns = dep.get("vulns", [])

                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN-CVE")
                    fix_versions = vuln.get("fix_versions", [])
                    fix_str = ", ".join(fix_versions) if fix_versions else "No fixed version reported yet"
                    desc = vuln.get("description", "Known security vulnerability in dependency.")

                    severity = Severity.HIGH
                    desc_lower = desc.lower()
                    if any(term in desc_lower for term in ("critical", "remote code execution", "rce", "arbitrary code")):
                        severity = Severity.CRITICAL
                    elif "moderate" in desc_lower or "low" in desc_lower:
                        severity = Severity.MEDIUM

                    findings.append(
                        Finding(
                            id=f"DEP-{vuln_id}-{name}",
                            title=f"Vulnerable dependency {name} ({vuln_id})",
                            severity=severity,
                            owasp_category=OWASPCategory.A06.value,
                            source=FindingSource.DEPENDENCIES,
                            file_path=str(file_path.relative_to(root)).replace("\\", "/"),
                            line_number=1,
                            description=f"{name}=={version} is affected by {vuln_id}: {desc[:250]}",
                            offending_snippet=f"{name}=={version}",
                            fix=f"Upgrade {name} to {fix_str} or latest safe release.",
                        )
                    )

        except Exception:
            continue

    return findings
