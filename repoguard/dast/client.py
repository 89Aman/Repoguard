import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Optional, Tuple


class HTTPResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], body: str, url: str):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.url = url


class DastClient:
    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 6.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        auth_token: Optional[str] = None,
    ) -> HTTPResponse:
        clean_path = path if path.startswith("/") else f"/{path}"
        target_url = f"{self.base_url}{clean_path}"

        req_headers = {
            "User-Agent": "RepoGuard-VAPT-Scanner/1.0",
            "Accept": "*/*",
        }

        active_token = auth_token if auth_token is not None else self.token
        if active_token:
            if active_token.lower().startswith("bearer ") or active_token.lower().startswith("token "):
                req_headers["Authorization"] = active_token
            else:
                req_headers["Authorization"] = f"Bearer {active_token}"

        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(
            url=target_url,
            data=body,
            headers=req_headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                return HTTPResponse(resp.status, resp_headers, resp_body, target_url)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
            err_headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
            return HTTPResponse(e.code, err_headers, err_body, target_url)
        except Exception as e:
            return HTTPResponse(0, {}, str(e), target_url)
