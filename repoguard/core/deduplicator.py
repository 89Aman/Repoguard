from typing import List
from repoguard.core.models import Finding, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    deduped: List[Finding] = []
    seen_map = {}

    for item in findings:
        file_key = None
        if item.file_path:
            norm_file = item.file_path.replace("\\", "/").lower()
            line_bucket = (item.line_number // 3) if item.line_number else 0
            file_key = f"{norm_file}:{line_bucket}:{item.owasp_category}"

        endpoint_key = None
        if item.endpoint:
            norm_endpoint = item.endpoint.lower()
            method = (item.http_method or "ANY").upper()
            endpoint_key = f"{norm_endpoint}:{method}:{item.owasp_category}"

        dedup_key = file_key or endpoint_key or f"{item.title}:{item.description[:60]}"

        if dedup_key in seen_map:
            existing_idx = seen_map[dedup_key]
            if SEVERITY_ORDER.get(item.severity, 99) < SEVERITY_ORDER.get(deduped[existing_idx].severity, 99):
                deduped[existing_idx] = item
            continue

        seen_map[dedup_key] = len(deduped)
        deduped.append(item)

    deduped.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.title))
    return deduped


def get_top_fixes(findings: List[Finding], limit: int = 12) -> List[Finding]:
    prioritized = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if len(prioritized) < limit:
        mediums = [f for f in findings if f.severity == Severity.MEDIUM]
        prioritized.extend(mediums[: limit - len(prioritized)])
    return prioritized[:limit]
