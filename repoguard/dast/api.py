import json
import re
from typing import List, Optional
from repoguard.core.models import EndpointInfo, Finding, FindingSource, OWASPCategory, Severity
from repoguard.dast.client import DastClient


def _is_stack_trace_leak(body: str) -> bool:
    body_lower = body.lower()
    indicators = [
        "traceback (most recent call last)",
        "sqlite3.operationalerror",
        "psycopg2.errors",
        "django.db.utils",
        "syntaxerror:",
        'file "',
        "exception value:",
    ]
    return any(ind in body_lower for ind in indicators)


def scan_live_apis(
    client: DastClient,
    endpoints: List[EndpointInfo],
    token2: Optional[str] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    if not endpoints:
        return findings

    rate_limit_tested = False

    for ep in endpoints:
        path = ep.path
        if "{" in path:
            test_path = re.sub(r"\{[^}]+\}", "1", path)
        else:
            test_path = path

        primary_method = ep.http_methods[0] if ep.http_methods else "GET"

        resp_no_token = client.request(
            method=primary_method,
            path=test_path,
            auth_token="",
        )

        if resp_no_token.status_code == 200 and len(resp_no_token.body.strip()) > 0:
            if ep.is_flagged or "login" not in test_path.lower():
                body_preview = resp_no_token.body[:300].replace("\n", " ")
                findings.append(
                    Finding(
                        id=f"DAST-API-UNAUTH-{test_path.strip('/').replace('/', '-')}-{primary_method}",
                        title=f"Unauthenticated data access on API endpoint: {test_path}",
                        severity=Severity.CRITICAL,
                        owasp_category=OWASPCategory.A01.value,
                        source=FindingSource.DAST_API,
                        endpoint=test_path,
                        http_method=primary_method,
                        description=f"Endpoint '{test_path}' returned HTTP 200 OK and data payload when queried with no authentication token. APIs must return 401 or 403.",
                        request_detail=f"{primary_method} {test_path} HTTP/1.1\nHost: {client.base_url}\nAuthorization: (None)",
                        response_detail=f"Status: {resp_no_token.status_code}\nPayload: {body_preview}",
                        fix="Enforce authentication and permission checks on this endpoint (e.g. IsAuthenticated). Return 401 Unauthorized for missing tokens.",
                    )
                )

        declared_upper = {m.upper() for m in ep.http_methods}
        candidate_tamper_methods = [m for m in ("DELETE", "PUT", "POST") if m not in declared_upper]

        for tm in candidate_tamper_methods:
            resp_tamper = client.request(method=tm, path=test_path)
            if resp_tamper.status_code in (200, 201, 204):
                findings.append(
                    Finding(
                        id=f"DAST-API-METHOD-TAMPER-{test_path.strip('/').replace('/', '-')}-{tm}",
                        title=f"Undeclared HTTP method {tm} accepted on {test_path}",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A01.value,
                        source=FindingSource.DAST_API,
                        endpoint=test_path,
                        http_method=tm,
                        description=f"Endpoint '{test_path}' declared methods {list(declared_upper)}, but successfully processed undeclared method {tm} with status {resp_tamper.status_code}.",
                        request_detail=f"{tm} {test_path} HTTP/1.1\nHost: {client.base_url}",
                        response_detail=f"Status: {resp_tamper.status_code}\nBody: {resp_tamper.body[:200]}",
                        fix="Strictly validate allowed HTTP methods and reject undeclared methods with 405 Method Not Allowed.",
                    )
                )
                break

        fuzz_methods = [m for m in ("POST", "PUT", "PATCH") if m in declared_upper] or ["POST"]
        for fm in fuzz_methods:
            malformed_body = b'{"query": 1, "data": '
            headers = {"Content-Type": "application/json"}
            resp_malformed = client.request(fm, test_path, headers=headers, body=malformed_body)

            if resp_malformed.status_code == 500 and _is_stack_trace_leak(resp_malformed.body):
                findings.append(
                    Finding(
                        id=f"DAST-API-STACKTRACE-{test_path.strip('/').replace('/', '-')}",
                        title=f"Stack trace or internal error leaked on malformed payload: {test_path}",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.DAST_API,
                        endpoint=test_path,
                        http_method=fm,
                        description=f"Sending malformed JSON to '{test_path}' triggered an unhandled server exception exposing traceback internals or database error details.",
                        request_detail=f"{fm} {test_path} HTTP/1.1\nContent-Type: application/json\n\n{malformed_body.decode('utf-8', errors='ignore')}",
                        response_detail=f"Status: {resp_malformed.status_code}\nBody: {resp_malformed.body[:350]}",
                        fix="Catch parsing and deserialization exceptions at controller layer and return structured 400 Bad Request error responses without tracebacks.",
                    )
                )
                break

        if not rate_limit_tested and primary_method == "GET":
            rate_limit_tested = True
            is_limited = False
            for _ in range(16):
                rl_res = client.request("GET", test_path)
                if rl_res.status_code == 429 or any("ratelimit" in k for k in rl_res.headers):
                    is_limited = True
                    break

            if not is_limited:
                findings.append(
                    Finding(
                        id="DAST-API-NO-RATE-LIMIT",
                        title=f"Missing rate limiting on API endpoints ({test_path})",
                        severity=Severity.MEDIUM,
                        owasp_category=OWASPCategory.A04.value,
                        source=FindingSource.DAST_API,
                        endpoint=test_path,
                        http_method="GET",
                        description=f"Burst of 16 rapid sequential requests to '{test_path}' succeeded without 429 throttling or rate-limiting headers.",
                        request_detail=f"16 rapid GET requests to {test_path}",
                        response_detail="All requests accepted with 200 OK",
                        fix="Configure global or endpoint rate limiting (e.g. django-ratelimit, DRF ScopedRateThrottle, or Nginx limit_req).",
                    )
                )

        if token2 and ("{" in ep.path or "/1" in test_path or "/detail" in test_path):
            resp_user1 = client.request("GET", test_path, auth_token=client.token)
            resp_user2 = client.request("GET", test_path, auth_token=token2)

            if resp_user1.status_code == 200 and resp_user2.status_code == 200:
                if len(resp_user1.body) > 10 and resp_user1.body == resp_user2.body:
                    findings.append(
                        Finding(
                            id=f"DAST-API-IDOR-{test_path.strip('/').replace('/', '-')}",
                            title=f"Broken Object Level Authorization (IDOR) on {test_path}",
                            severity=Severity.CRITICAL,
                            owasp_category=OWASPCategory.A01.value,
                            source=FindingSource.DAST_API,
                            endpoint=test_path,
                            http_method="GET",
                            description=f"User 2 was able to retrieve User 1's object data at '{test_path}' using their own valid token without ownership verification.",
                            request_detail=f"GET {test_path} with Token 2 credentials",
                            response_detail=f"Status: 200 OK\nPayload matches User 1 data",
                            fix="Verify requesting user owns or has explicit permission to access the target object ID before returning data.",
                        )
                    )

    return findings
