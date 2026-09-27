import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from repoguard.core.models import EndpointAuthStatus, EndpointInfo, Severity
from repoguard.dast.api_scanner import scan_live_apis
from repoguard.dast.app_scanner import scan_live_application
from repoguard.dast.client import DastClient


class MockVulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("Set-Cookie", "sessionid=xyz123; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body>Home Page</body></html>")
        elif self.path == "/api/insecure-data/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"secret_data": [1, 2, 3]}')
        elif "repoguard-error-trigger" in self.path:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Traceback (most recent call last):\nFile 'app.py'\nYou're seeing this error because you have <code>DEBUG = True</code>")
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path == "/api/insecure-data/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"deleted": true}')
        else:
            self.send_response(405)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/insecure-data/":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Traceback (most recent call last):\npsycopg2.errors.SyntaxError: syntax error at or near 'data'")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def test_dast_app_and_api_scanners():
    server = HTTPServer(("127.0.0.1", 0), MockVulnerableHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        client = DastClient(base_url=base_url)

        app_findings = scan_live_application(client)
        app_titles = [f.title for f in app_findings]

        assert any("Content-Security-Policy" in t for t in app_titles)
        assert any("X-Frame-Options" in t for t in app_titles)
        assert any("version disclosure" in t for t in app_titles)
        assert any("debug page" in t for t in app_titles)

        endpoints = [
            EndpointInfo(
                path="/api/insecure-data/",
                http_methods=["GET"],
                handler="insecure_view",
                auth_classes=[],
                permission_classes=[],
                status=EndpointAuthStatus.UNPROTECTED,
                is_flagged=True,
                notes="Unprotected test endpoint",
            )
        ]

        api_findings = scan_live_apis(client, endpoints)
        api_titles = [f.title for f in api_findings]

        assert any("Unauthenticated data access" in t for t in api_titles)
        assert any("Undeclared HTTP method DELETE" in t for t in api_titles)
        assert any("Stack trace" in t for t in api_titles)

        crit_findings = [f for f in api_findings if f.severity == Severity.CRITICAL]
        assert len(crit_findings) >= 1

    finally:
        server.shutdown()
        server.server_close()
