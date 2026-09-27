import datetime
from pathlib import Path
from typing import List, Optional, Tuple
from repoguard.api.discovery import discover_api_endpoints
from repoguard.core.deduplicator import deduplicate_findings, get_top_fixes
from repoguard.core.models import (
    EndpointInfo,
    Finding,
    ReportData,
    ScanSummary,
    Severity,
)
from repoguard.dast.api_scanner import scan_live_apis
from repoguard.dast.app_scanner import scan_live_application
from repoguard.dast.client import DastClient
from repoguard.report.generator import generate_reports
from repoguard.static.config_checker import scan_configuration
from repoguard.static.deps import scan_dependencies
from repoguard.static.hygiene import scan_repo_hygiene
from repoguard.static.sast import scan_sast
from repoguard.static.secrets import scan_secrets


def run_repoguard(
    repo_path: str,
    url: Optional[str] = None,
    token: Optional[str] = None,
    token2: Optional[str] = None,
    output_dir: str = "repoguard-output",
    deduplicate: bool = True,
) -> Tuple[ReportData, int]:
    scanned_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    all_findings: List[Finding] = []

    all_findings.extend(scan_dependencies(repo_path))
    all_findings.extend(scan_sast(repo_path))
    all_findings.extend(scan_secrets(repo_path))
    all_findings.extend(scan_configuration(repo_path))
    all_findings.extend(scan_repo_hygiene(repo_path))

    endpoints, api_findings = discover_api_endpoints(repo_path)
    all_findings.extend(api_findings)

    if url:
        client = DastClient(base_url=url, token=token)
        app_dast_findings = scan_live_application(client)
        all_findings.extend(app_dast_findings)

        api_dast_findings = scan_live_apis(client, endpoints, token2=token2)
        all_findings.extend(api_dast_findings)

    final_findings = deduplicate_findings(all_findings) if deduplicate else all_findings
    top_fixes = get_top_fixes(final_findings, limit=12)

    critical_count = sum(1 for f in final_findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in final_findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in final_findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in final_findings if f.severity == Severity.LOW)
    info_count = sum(1 for f in final_findings if f.severity == Severity.INFO)

    unprotected_eps = sum(1 for ep in endpoints if ep.is_flagged)

    summary = ScanSummary(
        target_path=str(Path(repo_path).resolve()),
        target_url=url,
        scanned_at=scanned_at,
        total_findings=len(final_findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        total_endpoints=len(endpoints),
        unprotected_endpoints=unprotected_eps,
    )

    report_data = ReportData(
        summary=summary,
        findings=final_findings,
        endpoints=endpoints,
        top_fixes=top_fixes,
    )

    generate_reports(report_data, output_dir)

    exit_code = 1 if critical_count > 0 else 0
    return report_data, exit_code
