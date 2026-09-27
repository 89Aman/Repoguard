# Assignment Submission Email

**Subject:** Submission: Python Repository VAPT Tool Assignment - RepoGuard

---

Dear Hiring Team / Evaluation Committee,

I have completed the technical assignment and built RepoGuard, an end-to-end Python repository security and VAPT scanner. The tool covers static analysis, API route discovery, dynamic application security testing (DAST), finding deduplication, and automated reporting.

The source code is hosted on GitHub, and the live scanning service is deployed on Google Cloud Run.

---

### Project Links
- GitHub Repository: https://github.com/89Aman/repoguard
- Live Cloud Run Service: https://repoguard-592636097524.us-central1.run.app
- Live DRF Testbed Report: https://repoguard-592636097524.us-central1.run.app/reports/drf
- Live PyGoat Benchmark Report: https://repoguard-592636097524.us-central1.run.app/reports/pygoat

---

### Summary of Completed Requirements

1. Static Security Analysis (SAST & Hygiene):
- Dependency vulnerabilities: Integrated pip-audit against PyPI advisories and OSV.
- Code-level SAST: AST-based and rule-based vulnerability scanning (Bandit and Semgrep integration).
- Secret detection: Entropy analysis and high-confidence regex patterns for API keys, private tokens, and passwords with Gitleaks support.
- Framework configuration audit: AST inspection of Django and Flask configuration files (DEBUG=True, SECRET_KEY exposure, ALLOWED_HOSTS, insecure session cookies).
- Repository hygiene: Automated detection of committed .env files, private keys, certificates, and database backups.

2. Static API Route Discovery & Permission Audit:
- AST route parser for Django, Django REST Framework, and Flask.
- Extracts HTTP methods, handler functions, route paths, and authentication/permission classes.
- Generates a route inventory and flags unprotected endpoints.

3. Dynamic Application Security Testing (DAST):
- Server security posture: Audits missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and cookie attributes (Secure, HttpOnly, SameSite).
- Information leakage: Sensitive file exposure (/metrics, /.git, /admin, debug pages).
- API vulnerability scanning: Unauthenticated endpoint verification, HTTP method tampering (HEAD/PUT/DELETE bypass), malformed JSON input resilience, rate-limiting checks, and automated IDOR (BOLA) testing using multi-token authorization validation.

4. Deduplication & Priority Triage:
- Consolidates overlapping findings across static and dynamic passes.
- Higher severity rules resolve duplicates to avoid noise.
- Generates a prioritized "Issues to Fix First" remediation action list.

5. Reporting & Cloud Deployment:
- Standalone, offline-ready HTML reports with responsive CSS, severity scorecards, and filtering.
- Machine-readable findings.json output for CI/CD pipelines.
- Dockerized container deployed on Google Cloud Run with an active web dashboard and on-demand scanning API.

---

### Quick Start (Local Reproduction)

Clone and run via Docker:
```bash
git clone https://github.com/89Aman/repoguard.git
cd repoguard
docker build -t repoguard .
docker run --rm -v $(pwd):/workspace repoguard scan .
```

Run test suite:
```bash
pytest -v
```

Please let me know if you have any questions or require additional demonstration.

Best regards,
Aman
GitHub: https://github.com/89Aman
