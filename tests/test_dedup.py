from repoguard.core.dedup import deduplicate_findings, get_top_fixes
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity


def test_deduplicator_merges_nearby_sast():
    f1 = Finding(
        id="BANDIT-B608-42",
        title="Bandit: Hardcoded sql expressions (B608)",
        severity=Severity.CRITICAL,
        owasp_category=OWASPCategory.A03.value,
        source=FindingSource.SAST,
        file_path="app/views.py",
        line_number=42,
        description="Possible SQL injection vector through string formatting",
        fix="Use parameterized queries",
    )
    f2 = Finding(
        id="SEMGREP-sqli-43",
        title="Semgrep: python.django.security.sqli",
        severity=Severity.HIGH,
        owasp_category=OWASPCategory.A03.value,
        source=FindingSource.SAST,
        file_path="app/views.py",
        line_number=43,
        description="User data directly interpolated into raw SQL query",
        fix="Use parameters argument",
    )
    f3 = Finding(
        id="CFG-DEBUG-10",
        title="Django DEBUG set to True",
        severity=Severity.HIGH,
        owasp_category=OWASPCategory.A05.value,
        source=FindingSource.CONFIGURATION,
        file_path="app/settings.py",
        line_number=10,
        description="DEBUG is enabled",
        fix="Disable debug",
    )

    combined = [f1, f2, f3]
    deduped = deduplicate_findings(combined)

    assert len(deduped) == 2
    assert deduped[0].severity == Severity.CRITICAL

    top = get_top_fixes(deduped, limit=1)
    assert len(top) == 1
    assert top[0].id == "BANDIT-B608-42"


def test_deduplicator_higher_severity_wins():
    f_low = Finding(
        id="LOW-1",
        title="Issue",
        severity=Severity.MEDIUM,
        owasp_category=OWASPCategory.A03.value,
        source=FindingSource.SAST,
        file_path="app/views.py",
        line_number=10,
        description="Medium issue",
        fix="Fix it",
    )
    f_high = Finding(
        id="HIGH-1",
        title="Issue",
        severity=Severity.CRITICAL,
        owasp_category=OWASPCategory.A03.value,
        source=FindingSource.SAST,
        file_path="app/views.py",
        line_number=11,
        description="Critical issue",
        fix="Fix it immediately",
    )

    deduped = deduplicate_findings([f_low, f_high])
    assert len(deduped) == 1
    assert deduped[0].severity == Severity.CRITICAL
    assert deduped[0].id == "HIGH-1"
