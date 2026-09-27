import tempfile
from pathlib import Path
from repoguard.core.models import Severity
from repoguard.static.hygiene import scan_repo_hygiene


def test_repo_hygiene_detects_sensitive_files():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / ".env").write_text("SECRET_KEY=12345", encoding="utf-8")
        (root / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----", encoding="utf-8")
        (root / "backup.sql").write_text("CREATE TABLE users ...", encoding="utf-8")
        (root / "server.crt").write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")

        findings = scan_repo_hygiene(tmp_dir)

        titles = [f.title for f in findings]
        assert any("Environment file" in t for t in titles)
        assert any("Private cryptographic key" in t for t in titles)
        assert any("Database dump" in t for t in titles)
        assert any("Certificate file" in t for t in titles)

        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        assert crit_count >= 2
