import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from repoguard.core.models import Finding
from repoguard.dast.app import scan_live_application
from repoguard.dast.api import scan_live_apis
from repoguard.dast.client import DastClient


def _find_report_file(rel_path: str) -> Optional[Path]:
    candidates = [
        Path(rel_path),
        Path("/workspace") / rel_path,
        Path("/app") / rel_path,
        Path(__file__).parent.parent / rel_path,
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


LANDING_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RepoGuard Cloud Service</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px; }
        .box { max-width: 900px; margin: 0 auto; background: #1e293b; padding: 32px; border-radius: 8px; border: 1px solid #334155; }
        h1 { margin-top: 0; font-size: 26px; }
        p { color: #94a3b8; font-size: 15px; line-height: 1.6; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 24px 0; }
        .card { background: #0f172a; border: 1px solid #334155; padding: 20px; border-radius: 6px; }
        .card h3 { margin-top: 0; font-size: 18px; color: #38bdf8; }
        .btn { display: inline-block; padding: 8px 16px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 4px; font-weight: 600; font-size: 13px; margin-top: 10px; }
        .btn-sub { background: #334155; margin-left: 8px; }
        .btn:hover { opacity: 0.9; }
        .api-form { margin-top: 32px; padding-top: 24px; border-top: 1px solid #334155; }
        input[type=text] { width: 70%; padding: 10px; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px; font-size: 14px; }
        button { padding: 10px 20px; background: #10b981; border: none; color: #fff; font-weight: 600; border-radius: 4px; cursor: pointer; font-size: 14px; }
        button:hover { background: #059669; }
        #results { margin-top: 16px; background: #090d16; border: 1px solid #334155; padding: 16px; border-radius: 6px; font-family: monospace; font-size: 12px; white-space: pre-wrap; display: none; }
    </style>
</head>
<body>
    <div class="box">
        <h1>RepoGuard Cloud VAPT Platform</h1>
        <p>Enterprise Python Repository & API Security Assessment Engine running on Google Cloud Run.</p>

        <h2>Committed Assessment Reports</h2>
        <div class="grid">
            <div class="card">
                <h3>DRF Testbed Scan</h3>
                <p>Evaluation against sample Django REST Framework app with intentionally exposed user endpoints and misconfigured settings.</p>
                <a href="/reports/drf" class="btn" target="_blank">View HTML Report</a>
                <a href="/reports/drf/findings.json" class="btn btn-sub" target="_blank">View JSON</a>
            </div>
            <div class="card">
                <h3>PyGoat Target Scan</h3>
                <p>Comprehensive static vulnerability and API endpoint assessment across the PyGoat vulnerable target repository.</p>
                <a href="/reports/pygoat" class="btn" target="_blank">View HTML Report</a>
                <a href="/reports/pygoat/findings.json" class="btn btn-sub" target="_blank">View JSON</a>
            </div>
        </div>

        <div class="api-form">
            <h2>Live Target DAST Scanner</h2>
            <p>Scan a live web application or API endpoint directly from Cloud Run:</p>
            <form onsubmit="runScan(event)">
                <input type="text" id="targetUrl" placeholder="https://example.com" required>
                <button type="submit">Scan Target</button>
            </form>
            <div id="results"></div>
        </div>
    </div>

    <script>
        async function runScan(e) {
            e.preventDefault();
            const url = document.getElementById('targetUrl').value;
            const resDiv = document.getElementById('results');
            resDiv.style.display = 'block';
            resDiv.textContent = 'Scanning target ' + url + '...';

            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const data = await resp.json();
                resDiv.textContent = JSON.stringify(data, null, 2);
            } catch (err) {
                resDiv.textContent = 'Error: ' + err.message;
            }
        }
    </script>
</body>
</html>
"""


class RepoGuardServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/health":
            self._send_json(200, {"status": "ok", "service": "repoguard", "version": "0.1.0"})
        elif path in ("", "/"):
            self._send_html(200, LANDING_PAGE_HTML)
        elif path == "/reports/drf":
            self._serve_file("reports/drf/report.html", "text/html")
        elif path == "/reports/drf/findings.json":
            self._serve_file("reports/drf/findings.json", "application/json")
        elif path == "/reports/pygoat":
            self._serve_file("reports/pygoat/report.html", "text/html")
        elif path == "/reports/pygoat/findings.json":
            self._serve_file("reports/pygoat/findings.json", "application/json")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/scan":
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
                payload = json.loads(raw_body)
                target_url = payload.get("url")

                if not target_url:
                    self._send_json(400, {"error": "Missing 'url' parameter in payload."})
                    return

                client = DastClient(base_url=target_url, token=payload.get("token"))
                findings = scan_live_application(client)
                dict_findings = [f.model_dump() for f in findings]

                self._send_json(200, {
                    "target_url": target_url,
                    "findings_count": len(dict_findings),
                    "findings": dict_findings,
                })
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_file(self, rel_path: str, content_type: str):
        file_path = _find_report_file(rel_path)
        if file_path:
            with open(file_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Report not found on server")

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def run_web_server(host: str = "0.0.0.0", port: int = 8080):
    server = HTTPServer((host, port), RepoGuardServer)
    print(f"RepoGuard server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
