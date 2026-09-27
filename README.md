# RepoGuard: Repository VAPT Security Scanner

RepoGuard is an end-to-end vulnerability assessment and penetration testing (VAPT) CLI tool designed to inspect Python codebases, running web applications, and exposed APIs. It runs locally or inside a self-contained Docker container, producing a unified, prioritized report showing what is vulnerable and what to fix first.

---

## Capabilities

### Part 1: Static Assessment
- **Dependencies**: Identifies known CVEs in `requirements*.txt`, `poetry.lock`, and `Pipfile.lock` using `pip-audit`, detailing severity, CVE ID, and fixed versions.
- **Code (SAST)**: Runs `bandit` and `semgrep` to detect SQL injection, command execution, unsafe deserialization, weak cryptographic ciphers, and path traversal.
- **Secrets**: Scans source code and Git history using `gitleaks` (with regex pattern fallback) for API keys, tokens, and private credentials.
- **Configuration Auditor**: Custom AST-based static analyzer inspecting Django and Flask settings for:
  - `DEBUG = True`
  - `ALLOWED_HOSTS = ['*']`
  - Hardcoded `SECRET_KEY` or plaintext database passwords
  - Missing `SecurityMiddleware` and `CsrfViewMiddleware`
  - Insecure session and CSRF cookie flags (`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`)
  - `CORS_ALLOW_ALL_ORIGINS = True`
  - `app.run(debug=True)` in Flask applications
- **Repo Hygiene**: Detects committed `.env` files, private keys (`.pem`, `.key`, `id_rsa`), certificates, and database dumps (`.sql`, `.sqlite3`).

### Part 2: API Discovery
- **Route Extraction**: Statically parses Django `urls.py` and DRF routers (`DefaultRouter`, `SimpleRouter`), as well as Flask `@app.route` decorators.
- **Authentication & Permission Classification**: Traces views and viewsets to evaluate `permission_classes`, `authentication_classes`, and decorators (`@login_required`).
- **Policy Flagging**: Flags unauthenticated routes and endpoints defaulting to global `AllowAny`.
- **Inventory Reporting**: Outputs a tabular endpoint inventory mapping paths, allowed HTTP methods, handler views, and protection status.

### Part 3: Live Application & API Testing (DAST)
When a live target `--url` is provided:
- **Application Level**:
  - Missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.
  - Cookies lacking `Secure`, `HttpOnly`, or `SameSite`.
  - Exposed sensitive paths: `/admin`, `/.env`, `/.git/HEAD`.
  - Detection of Django interactive debug screens or stack traces upon errors.
- **API Level**:
  - **Unauthenticated Probe**: Calls endpoints without authentication tokens; flags any 200 OK responses returning sensitive data instead of 401/403 as Critical.
  - **HTTP Method Tampering**: Tests undeclared HTTP methods (PUT, DELETE, POST) against GET-only endpoints.
  - **Payload Error Fuzzing**: Sends malformed and oversized payloads to check for unhandled 500 exceptions leaking SQL errors, internal file paths, or tracebacks.
  - **Rate Limiting Check**: Sends burst requests to assess throttling behavior.
  - **IDOR Check (Bonus)**: Given `--token` and `--token2`, tests cross-tenant object access.

### Reporting & Triage
- Generates an interactive standalone HTML dashboard (`report.html`) with embedded styling (no external CDN requirements) and a machine-readable `findings.json`.
- **De-duplication Engine**: Consolidates overlapping findings across Bandit, Semgrep, and static checks.
- **Priority Triage**: Highlights the top critical and high issues to fix first.
- **Exit Code**: Returns exit code `1` when Critical findings exist, enabling CI/CD pipeline integration.

---

## Quickstart

### Option A: Running via Docker (Recommended, Zero Host Dependencies)

Build the image:
```bash
docker build -t repoguard .
```

Static assessment only:
```bash
docker run --rm -v $(pwd):/workspace repoguard scan .
```

Static and live application/API assessment:
```bash
docker run --rm --network host -v $(pwd):/workspace repoguard scan . --url http://localhost:8000
```

With authentication token:
```bash
docker run --rm --network host -v $(pwd):/workspace repoguard scan . --url http://localhost:8000 --token "your-auth-token"
```

Using Docker Compose:
```bash
docker-compose run --rm repoguard scan . --url http://localhost:8000
```

### Option B: Running Locally

Prerequisites: Python 3.10+

1. Create a virtual environment and install RepoGuard:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

2. Run static scan:
```bash
python -m repoguard scan .
```

3. Run full static + live DAST scan:
```bash
python -m repoguard scan . --url http://localhost:8000
```

4. View reports in `./repoguard-output/`:
- HTML Report: `repoguard-output/report.html`
- JSON Findings: `repoguard-output/findings.json`

---

## Architecture & Design Decisions

1. **Static AST Analysis over Dynamic Runtime Execution**:
   - *Decision*: Django settings and routes are parsed using Python's standard `ast` module rather than importing Django runtime modules (`django.setup()`).
   - *Rationale*: Running `import settings` in untrusted foreign repositories requires valid database connections, system packages, and environment variables. If any dependency is broken, dynamic analysis crashes before scanning begins. AST inspection runs reliably in milliseconds with zero side effects.

2. **Deduplication and Signal-to-Noise Ratio**:
   - *Decision*: Findings across overlapping SAST engines (Bandit and Semgrep) within proximity buckets (+/- 2 lines) and matching categories are automatically merged.
   - *Rationale*: A security engineer cannot triage 400 redundant alerts. Surfacing the unique, actionable issues and sorting by severity (Critical first) provides immediate engineering value.

3. **Self-Contained Offline HTML Reporting**:
   - *Decision*: The HTML template uses vanilla CSS and zero external CDNs or JavaScript frameworks.
   - *Rationale*: Reports are frequently viewed on air-gapped CI servers, isolated development networks, or compliance archives without internet connectivity.

4. **Non-Destructive DAST Probing**:
   - *Decision*: Dynamic probes focus on authorization boundaries, method enforcement, and error leakage rather than aggressive brute force or destructive payloads.
   - *Rationale*: Guarantees that live testbed databases and application states remain intact while verifying critical security controls.

---

## Known Limitations & What Is Not Done

1. **Dynamic Meta-programmed Routes**:
   - URLs dynamically generated via complex runtime decorators, custom metaclasses, or dynamic string concatenation are not fully resolved by the static AST parser.
2. **GraphQL and WebSocket Endpoints**:
   - Discovery currently targets REST/HTTP endpoints. GraphQL introspection and WebSocket handshake security are outside current scope.
3. **Stateful Multi-step Business Logic**:
   - The DAST engine validates single-request authorization and fuzzing; complex multi-step workflows (e.g. 3-step checkout or workflow approval logic) require specialized functional testing scripts.

---

## Verification Testbeds

Reports from verified test runs are committed in the `reports/` directory:
- `reports/drf_report.html` & `reports/drf_findings.json`: Scan of the Django REST Framework testbed (`testbeds/drf_sample/`).
- `reports/pygoat_report.html` & `reports/pygoat_findings.json`: Scan of the PyGoat vulnerable target.
