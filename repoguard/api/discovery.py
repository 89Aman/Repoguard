from pathlib import Path
from typing import List, Tuple
from repoguard.api.django import parse_django_urls, parse_view_definitions
from repoguard.api.flask import parse_flask_routes
from repoguard.core.models import EndpointAuthStatus, EndpointInfo, Finding, FindingSource, OWASPCategory, Severity


def discover_api_endpoints(repo_path: str) -> Tuple[List[EndpointInfo], List[Finding]]:
    root = Path(repo_path)
    endpoints: List[EndpointInfo] = []
    findings: List[Finding] = []

    views = parse_view_definitions(root)
    django_eps = parse_django_urls(root, views, global_allow_any=True)
    endpoints.extend(django_eps)

    flask_eps = parse_flask_routes(root)
    endpoints.extend(flask_eps)

    seen = set()
    unique_endpoints: List[EndpointInfo] = []
    for ep in endpoints:
        key = (ep.path, tuple(sorted(ep.http_methods)))
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)

    for ep in unique_endpoints:
        if ep.is_flagged:
            severity = Severity.HIGH if any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods) else Severity.MEDIUM
            if ep.status == EndpointAuthStatus.ALLOW_ANY_DEFAULT:
                title = f"API Endpoint relying on global AllowAny: {ep.path}"
                desc = f"Endpoint '{ep.path}' [{', '.join(ep.http_methods)}] has no explicit permission class and inherits the project's global AllowAny default."
            else:
                title = f"Unprotected API Endpoint: {ep.path}"
                desc = f"Endpoint '{ep.path}' [{', '.join(ep.http_methods)}] exposes functionality without authentication or permission verification."

            findings.append(
                Finding(
                    id=f"API-AUTH-{len(findings) + 1}",
                    title=title,
                    severity=severity,
                    owasp_category=OWASPCategory.A01.value,
                    source=FindingSource.API_DISCOVERY,
                    endpoint=ep.path,
                    http_method=", ".join(ep.http_methods),
                    description=desc,
                    offending_snippet=f"Handler: {ep.handler}",
                    fix="Explicitly assign authentication and permission classes (e.g. permission_classes = [IsAuthenticated]) or require session login.",
                )
            )

    return unique_endpoints, findings
