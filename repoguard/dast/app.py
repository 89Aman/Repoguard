import re
from typing import List
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity
from repoguard.dast.client import DastClient


def scan_live_application(client: DastClient) -> List[Finding]:
    findings: List[Finding] = []

    resp = client.request("GET", "/")
    if resp.status_code == 0:
        findings.append(
            Finding(
                id="DAST-APP-UNREACHABLE",
                title="Target unreachable",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description=f"Cannot reach {client.base_url}: {resp.body}",
                fix="Start server at target URL.",
            )
        )
        return findings

    headers = resp.headers

    if "content-security-policy" not in headers:
        findings.append(
            Finding(
                id="DAST-HDR-MISSING-CSP",
                title="Missing Content-Security-Policy header",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="Content-Security-Policy missing. Vulnerable to XSS.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}\nHeaders: {headers}",
                fix="Add Content-Security-Policy: default-src 'self'.",
            )
        )

    if client.base_url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="DAST-HDR-MISSING-HSTS",
                title="Missing HSTS header",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="Strict-Transport-Security missing on HTTPS.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}",
                fix="Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            )
        )

    if "x-frame-options" not in headers:
        findings.append(
            Finding(
                id="DAST-HDR-MISSING-XFO",
                title="Missing X-Frame-Options header",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="X-Frame-Options missing. Vulnerable to clickjacking.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}",
                fix="Set X-Frame-Options to DENY or SAMEORIGIN.",
            )
        )

    if "x-content-type-options" not in headers:
        findings.append(
            Finding(
                id="DAST-HDR-MISSING-XCTO",
                title="Missing X-Content-Type-Options header",
                severity=Severity.LOW,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="X-Content-Type-Options missing. MIME sniffing risk.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}",
                fix="Set X-Content-Type-Options: nosniff.",
            )
        )

    server_val = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if re.search(r"\d", server_val) or powered_by:
        findings.append(
            Finding(
                id="DAST-HDR-VERSION-DISCLOSURE",
                title="Server version disclosure in headers",
                severity=Severity.LOW,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description=f"Headers expose version: {server_val} {powered_by}".strip(),
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Server: {server_val}\nX-Powered-By: {powered_by}",
                fix="Hide Server and X-Powered-By banners.",
            )
        )

    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        cookie_lower = raw_cookie.lower()
        if "secure" not in cookie_lower and client.base_url.startswith("https://"):
            findings.append(
                Finding(
                    id="DAST-COOKIE-MISSING-SECURE",
                    title="Cookie missing Secure flag",
                    severity=Severity.MEDIUM,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    description="Cookie sent without Secure flag over HTTPS.",
                    offending_snippet=raw_cookie[:100],
                    fix="Add Secure flag to cookies.",
                )
            )
        if "httponly" not in cookie_lower:
            findings.append(
                Finding(
                    id="DAST-COOKIE-MISSING-HTTPONLY",
                    title="Cookie missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    description="Cookie accessible via JavaScript.",
                    offending_snippet=raw_cookie[:100],
                    fix="Add HttpOnly flag to cookies.",
                )
            )
        if "samesite" not in cookie_lower:
            findings.append(
                Finding(
                    id="DAST-COOKIE-MISSING-SAMESITE",
                    title="Cookie missing SameSite flag",
                    severity=Severity.LOW,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    description="Cookie missing SameSite attribute.",
                    offending_snippet=raw_cookie[:100],
                    fix="Set SameSite=Lax or Strict.",
                )
            )

    paths_to_probe = [
        ("/.git/HEAD", "Git repository metadata exposed", Severity.CRITICAL, "ref: refs/"),
        ("/.env", "Environment file exposed", Severity.CRITICAL, "="),
        ("/admin/", "Admin interface exposed", Severity.LOW, "admin"),
        ("/admin/login/", "Admin login portal exposed", Severity.LOW, "login"),
    ]

    for probe_path, probe_title, probe_sev, indicator in paths_to_probe:
        probe_res = client.request("GET", probe_path)
        if probe_res.status_code == 200 and indicator in probe_res.body.lower():
            findings.append(
                Finding(
                    id=f"DAST-PATH-{probe_path.strip('/').replace('/', '-')}",
                    title=probe_title,
                    severity=probe_sev,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    endpoint=probe_path,
                    http_method="GET",
                    description=f"Path '{probe_path}' returned 200 OK with sensitive contents.",
                    request_detail=f"GET {probe_path} HTTP/1.1\nHost: {client.base_url}",
                    response_detail=f"Status: 200\nPreview: {probe_res.body[:200]}",
                    fix=f"Block '{probe_path}' at proxy/gateway.",
                )
            )

    err_res = client.request("GET", "/repoguard-error-trigger-random-path-404-check/")
    body_err = err_res.body
    if any(sig in body_err for sig in ("You're seeing this error because you have <code>DEBUG = True</code>", "Traceback (most recent call last):", "Django Version:", "Exception Type:")):
        findings.append(
            Finding(
                id="DAST-APP-DEBUG-PAGE-EXPOSED",
                title="Django debug page exposed",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="Live app leaked Django debug error page.",
                request_detail=f"GET /repoguard-error-trigger-random-path-404-check/ HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {err_res.status_code}\nSnippet: {body_err[:300]}",
                fix="Set DEBUG = False in production settings.",
            )
        )

    return findings
