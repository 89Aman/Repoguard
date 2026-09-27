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
                title="Target application is unreachable",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description=f"Could not establish HTTP connection to {client.base_url}: {resp.body}",
                fix="Ensure the web server is booted and accessible at the specified URL.",
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
                description="The response header Content-Security-Policy is not set, leaving users vulnerable to Cross-Site Scripting (XSS) and data injection.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}\nHeaders: {headers}",
                fix="Implement a restrictive Content-Security-Policy (e.g. default-src 'self').",
            )
        )

    if client.base_url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="DAST-HDR-MISSING-HSTS",
                title="Missing HTTP Strict Transport Security (HSTS) header",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="The Strict-Transport-Security header is not configured on HTTPS endpoint, allowing potential SSL stripping attacks.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}",
                fix="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to response headers.",
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
                description="The X-Frame-Options header is missing, allowing pages to be framed by malicious sites for Clickjacking attacks.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}",
                fix="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
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
                description="The X-Content-Type-Options header is missing. Browsers may MIME-sniff the response, leading to unexpected script execution.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {resp.status_code}",
                fix="Set 'X-Content-Type-Options: nosniff'.",
            )
        )

    server_val = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if re.search(r"\d", server_val) or powered_by:
        findings.append(
            Finding(
                id="DAST-HDR-VERSION-DISCLOSURE",
                title="Server and framework version disclosure in HTTP headers",
                severity=Severity.LOW,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description=f"Server exposes version signatures: Server: '{server_val}', X-Powered-By: '{powered_by}'. This aids attackers in fingerprinting known CVEs.",
                request_detail=f"GET / HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Server: {server_val}\nX-Powered-By: {powered_by}",
                fix="Strip or suppress Server and X-Powered-By header banners in web server / reverse proxy configuration.",
            )
        )

    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        cookie_lower = raw_cookie.lower()
        if "secure" not in cookie_lower and client.base_url.startswith("https://"):
            findings.append(
                Finding(
                    id="DAST-COOKIE-MISSING-SECURE",
                    title="Cookie issued without Secure flag",
                    severity=Severity.MEDIUM,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    description="Session or tracking cookie is set without the Secure attribute, permitting transmission over cleartext HTTP.",
                    offending_snippet=raw_cookie[:100],
                    fix="Set the Secure flag on all Set-Cookie directives.",
                )
            )
        if "httponly" not in cookie_lower:
            findings.append(
                Finding(
                    id="DAST-COOKIE-MISSING-HTTPONLY",
                    title="Cookie issued without HttpOnly flag",
                    severity=Severity.MEDIUM,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    description="Cookie is accessible via client-side JavaScript (document.cookie), enabling session theft via XSS.",
                    offending_snippet=raw_cookie[:100],
                    fix="Add the HttpOnly attribute to sensitive session and auth cookies.",
                )
            )
        if "samesite" not in cookie_lower:
            findings.append(
                Finding(
                    id="DAST-COOKIE-MISSING-SAMESITE",
                    title="Cookie issued without SameSite flag",
                    severity=Severity.LOW,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.DAST_APP,
                    description="Cookie does not declare SameSite attribute, which increases susceptibility to Cross-Site Request Forgery.",
                    offending_snippet=raw_cookie[:100],
                    fix="Set 'SameSite=Lax' or 'SameSite=Strict' on all cookies.",
                )
            )

    paths_to_probe = [
        ("/.git/HEAD", "Git repository metadata exposed", Severity.CRITICAL, "ref: refs/"),
        ("/.env", "Environment variable file exposed over HTTP", Severity.CRITICAL, "="),
        ("/admin/", "Administrative interface exposed publicly", Severity.LOW, "admin"),
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
                    description=f"Path '{probe_path}' responded with 200 OK containing expected sensitive content indicator.",
                    request_detail=f"GET {probe_path} HTTP/1.1\nHost: {client.base_url}",
                    response_detail=f"Status: 200\nBody Preview: {probe_res.body[:200]}",
                    fix=f"Block access to '{probe_path}' in web server / reverse proxy rules.",
                )
            )

    err_res = client.request("GET", "/repoguard-error-trigger-random-path-404-check/")
    body_err = err_res.body
    if any(sig in body_err for sig in ("You're seeing this error because you have <code>DEBUG = True</code>", "Traceback (most recent call last):", "Django Version:", "Exception Type:")):
        findings.append(
            Finding(
                id="DAST-APP-DEBUG-PAGE-EXPOSED",
                title="Django interactive debug page exposed on live server",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05.value,
                source=FindingSource.DAST_APP,
                description="Live application returns full Django interactive debug error page upon 404/500 errors, exposing project settings, source code paths, and environment internals.",
                request_detail=f"GET /repoguard-error-trigger-random-path-404-check/ HTTP/1.1\nHost: {client.base_url}",
                response_detail=f"Status: {err_res.status_code}\nSnippet: {body_err[:300]}",
                fix="Set DEBUG = False in production settings to ensure generic 404 and 500 error templates are displayed.",
            )
        )

    return findings
