import os
from pathlib import Path
from typing import List
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity

EXCLUDED_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "repoguard-output", "reports"}

PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
PRIVATE_KEY_EXTS = {".pem", ".key", ".pkcs8"}
CERT_EXTS = {".crt", ".cer", ".pfx", ".p12"}
DB_EXTS = {".sql", ".dump", ".sqlite", ".sqlite3", ".db"}


def scan_repo_hygiene(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    root = Path(repo_path)

    for item in root.rglob("*"):
        if not item.is_file():
            continue

        parts = item.relative_to(root).parts
        if any(p in EXCLUDED_DIRS for p in parts):
            continue

        rel_path = str(item.relative_to(root)).replace("\\", "/")
        name_lower = item.name.lower()
        ext_lower = item.suffix.lower()

        if name_lower == ".env" or name_lower.startswith(".env."):
            findings.append(
                Finding(
                    id=f"HYG-ENV-{len(findings) + 1}",
                    title="Environment file committed to repository",
                    severity=Severity.CRITICAL,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.REPO_HYGIENE,
                    file_path=rel_path,
                    line_number=1,
                    description=f"Environment variable file '{rel_path}' is committed. This frequently leaks API tokens, database credentials, and secret keys.",
                    offending_snippet=f"File: {rel_path}",
                    fix="Remove .env files from git tracking, add to .gitignore, and rotate any exposed credentials immediately.",
                )
            )

        elif name_lower in PRIVATE_KEY_NAMES or ext_lower in PRIVATE_KEY_EXTS:
            findings.append(
                Finding(
                    id=f"HYG-KEY-{len(findings) + 1}",
                    title="Private cryptographic key committed to repository",
                    severity=Severity.CRITICAL,
                    owasp_category=OWASPCategory.A02.value,
                    source=FindingSource.REPO_HYGIENE,
                    file_path=rel_path,
                    line_number=1,
                    description=f"Private key file '{rel_path}' detected in repository. Compromised private keys break TLS/SSH authentication and encryption integrity.",
                    offending_snippet=f"File: {rel_path}",
                    fix="Remove private key file from git, add pattern to .gitignore, and revoke/re-issue keys immediately.",
                )
            )

        elif ext_lower in DB_EXTS:
            findings.append(
                Finding(
                    id=f"HYG-DB-{len(findings) + 1}",
                    title="Database dump or SQLite database committed to repository",
                    severity=Severity.HIGH,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.REPO_HYGIENE,
                    file_path=rel_path,
                    line_number=1,
                    description=f"Database file or SQL dump '{rel_path}' is committed in the repository, potentially exposing schema structure, customer data, and credential hashes.",
                    offending_snippet=f"File: {rel_path}",
                    fix="Remove database dump from source control, add database file extensions to .gitignore, and purge from git history.",
                )
            )

        elif ext_lower in CERT_EXTS:
            findings.append(
                Finding(
                    id=f"HYG-CERT-{len(findings) + 1}",
                    title="Certificate file committed to repository",
                    severity=Severity.LOW,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.REPO_HYGIENE,
                    file_path=rel_path,
                    line_number=1,
                    description=f"Certificate file '{rel_path}' detected. While public certificates are non-secret, bundle files (.pfx/.p12) often contain private keys.",
                    offending_snippet=f"File: {rel_path}",
                    fix="Verify certificates do not contain embedded private keys and manage certificates outside of code repositories.",
                )
            )

    return findings
