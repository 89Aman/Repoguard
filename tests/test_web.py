import threading
import urllib.request
from http.server import HTTPServer
from repoguard.web import RepoGuardServer


def test_web_server_endpoints():
    server = HTTPServer(("127.0.0.1", 0), RepoGuardServer)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    base_url = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(f"{base_url}/health") as resp:
            assert resp.status == 200
            body = resp.read().decode()
            assert "repoguard" in body

        with urllib.request.urlopen(f"{base_url}/") as resp:
            assert resp.status == 200
            html = resp.read().decode()
            assert "RepoGuard Cloud VAPT Platform" in html
    finally:
        server.shutdown()
        server.server_close()
