import ast
import os
import re
from pathlib import Path
from typing import List, Optional, Set
from repoguard.core.models import Finding, FindingSource, OWASPCategory, Severity


class ConfigVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.findings: List[Finding] = []
        self.is_django = "settings" in file_path.lower() or "DJANGO" in source_code
        self.is_flask = "flask" in source_code.lower() or "app.py" in file_path.lower()

        self.assigned_vars: dict = {}
        self.middleware_list: Optional[List[str]] = None
        self.database_passwords: List[tuple] = []

    def _get_snippet(self, node: ast.AST) -> str:
        line_no = getattr(node, "lineno", 1)
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1].strip()
        return ""

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                self._check_variable_assignment(var_name, node.value, node)
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                if target.value.id == "app" and target.attr == "secret_key":
                    self._check_secret_key("app.secret_key", node.value, node)
            elif isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Attribute) and target.value.attr == "config":
                    if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                        self._check_flask_config_key(target.slice.value, node.value, node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        Finding(
                            id=f"CFG-FLASK-DEBUG-{getattr(node, 'lineno', 1)}",
                            title="Flask debug mode enabled in app.run",
                            severity=Severity.HIGH,
                            owasp_category=OWASPCategory.A05.value,
                            source=FindingSource.CONFIGURATION,
                            file_path=self.file_path,
                            line_number=getattr(node, "lineno", 1),
                            description="Flask application is launched with debug=True, enabling the interactive Werkzeug debugger which permits remote code execution.",
                            offending_snippet=self._get_snippet(node),
                            fix="Set debug=False or remove debug argument before deployment. Use production WSGI server (Gunicorn/Uvicorn).",
                        )
                    )
        self.generic_visit(node)

    def _check_variable_assignment(self, name: str, value_node: ast.AST, assign_node: ast.Assign):
        lineno = getattr(assign_node, "lineno", 1)
        snippet = self._get_snippet(assign_node)

        if name == "DEBUG":
            if isinstance(value_node, ast.Constant) and value_node.value is True:
                self.findings.append(
                    Finding(
                        id=f"CFG-DEBUG-TRUE-{lineno}",
                        title="Django DEBUG set to True",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=lineno,
                        description="DEBUG mode is enabled. Detailed error pages expose stack traces, settings, and internal variables to users.",
                        offending_snippet=snippet,
                        fix="Set DEBUG = False or load from environment variable (e.g. os.getenv('DJANGO_DEBUG', 'False').lower() in ('true', '1')).",
                    )
                )

        elif name == "ALLOWED_HOSTS":
            hosts = self._extract_list_constants(value_node)
            if "*" in hosts:
                self.findings.append(
                    Finding(
                        id=f"CFG-ALLOWED-HOSTS-{lineno}",
                        title="Django ALLOWED_HOSTS wildcard enabled",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=lineno,
                        description="ALLOWED_HOSTS contains '*' which permits Host header poisoning attacks, cache poisoning, and password reset poisoning.",
                        offending_snippet=snippet,
                        fix="Specify explicit domain names or hostnames in ALLOWED_HOSTS.",
                    )
                )

        elif name == "SECRET_KEY":
            self._check_secret_key(name, value_node, assign_node)

        elif name in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
            self.middleware_list = self._extract_list_constants(value_node)

        elif name == "DATABASES":
            self._check_database_passwords(value_node, lineno)

        elif name == "SESSION_COOKIE_SECURE":
            if isinstance(value_node, ast.Constant) and value_node.value is False:
                self.findings.append(
                    Finding(
                        id=f"CFG-SESSION-COOKIE-SECURE-{lineno}",
                        title="SESSION_COOKIE_SECURE is disabled",
                        severity=Severity.MEDIUM,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=lineno,
                        description="SESSION_COOKIE_SECURE = False allows session cookies to be transmitted over unencrypted HTTP connections.",
                        offending_snippet=snippet,
                        fix="Set SESSION_COOKIE_SECURE = True in production settings.",
                    )
                )

        elif name == "CSRF_COOKIE_SECURE":
            if isinstance(value_node, ast.Constant) and value_node.value is False:
                self.findings.append(
                    Finding(
                        id=f"CFG-CSRF-COOKIE-SECURE-{lineno}",
                        title="CSRF_COOKIE_SECURE is disabled",
                        severity=Severity.MEDIUM,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=lineno,
                        description="CSRF_COOKIE_SECURE = False allows CSRF tokens to be transmitted over unencrypted HTTP connections.",
                        offending_snippet=snippet,
                        fix="Set CSRF_COOKIE_SECURE = True in production settings.",
                    )
                )

        elif name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"):
            if isinstance(value_node, ast.Constant) and value_node.value is True:
                self.findings.append(
                    Finding(
                        id=f"CFG-CORS-ALL-{lineno}",
                        title="CORS configured to allow all origins",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=lineno,
                        description=f"{name} = True permits any external origin to read sensitive cross-origin API responses.",
                        offending_snippet=snippet,
                        fix="Set CORS_ALLOW_ALL_ORIGINS = False and specify trusted origins in CORS_ALLOWED_ORIGINS.",
                    )
                )

    def _check_flask_config_key(self, key: str, value_node: ast.AST, node: ast.AST):
        lineno = getattr(node, "lineno", 1)
        snippet = self._get_snippet(node)
        if key == "SECRET_KEY":
            self._check_secret_key(f"config['{key}']", value_node, node)
        elif key == "DEBUG" and isinstance(value_node, ast.Constant) and value_node.value is True:
            self.findings.append(
                Finding(
                    id=f"CFG-FLASK-DEBUG-CONF-{lineno}",
                    title="Flask DEBUG configured to True",
                    severity=Severity.HIGH,
                    owasp_category=OWASPCategory.A05.value,
                    source=FindingSource.CONFIGURATION,
                    file_path=self.file_path,
                    line_number=lineno,
                    description="Flask debug mode is enabled via config, permitting debugger interaction and stack trace exposure.",
                    offending_snippet=snippet,
                    fix="Disable debug mode in production environment.",
                )
            )

    def _check_secret_key(self, name: str, value_node: ast.AST, node: ast.AST):
        lineno = getattr(node, "lineno", 1)
        snippet = self._get_snippet(node)
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            val = value_node.value.strip()
            if len(val) > 0 and not val.startswith("env(") and not val.startswith("os."):
                self.findings.append(
                    Finding(
                        id=f"CFG-HARDCODED-SECRET-KEY-{lineno}",
                        title=f"Hardcoded {name} found in settings",
                        severity=Severity.CRITICAL,
                        owasp_category=OWASPCategory.A02.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=lineno,
                        description="SECRET_KEY is hardcoded in source code. Anyone with access to the repo can forge session cookies, sign malicious tokens, and bypass authentication.",
                        offending_snippet=snippet,
                        fix="Load SECRET_KEY from an environment variable (e.g. os.environ['SECRET_KEY']) or secret manager.",
                    )
                )

    def _check_database_passwords(self, node: ast.AST, lineno: int):
        if isinstance(node, ast.Dict):
            for val in node.values:
                if isinstance(val, ast.Dict):
                    for k, v in zip(val.keys, val.values):
                        if isinstance(k, ast.Constant) and str(k.value).upper() == "PASSWORD":
                            if isinstance(v, ast.Constant) and isinstance(v.value, str) and len(v.value) > 0:
                                self.findings.append(
                                    Finding(
                                        id=f"CFG-DB-PASSWORD-{lineno}",
                                        title="Hardcoded database password in settings",
                                        severity=Severity.CRITICAL,
                                        owasp_category=OWASPCategory.A07.value,
                                        source=FindingSource.CONFIGURATION,
                                        file_path=self.file_path,
                                        line_number=lineno,
                                        description="Database connection configuration contains a hardcoded plaintext password.",
                                        offending_snippet=f"PASSWORD: '***'",
                                        fix="Supply database password via environment variables or secret store.",
                                    )
                                )

    def _extract_list_constants(self, node: ast.AST) -> List[str]:
        items: List[str] = []
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    items.append(elt.value)
        return items

    def finalize(self):
        if self.is_django and self.middleware_list is not None:
            has_security = any("SecurityMiddleware" in m for m in self.middleware_list)
            has_csrf = any("CsrfViewMiddleware" in m for m in self.middleware_list)

            if not has_security:
                self.findings.append(
                    Finding(
                        id="CFG-MISSING-SECURITY-MIDDLEWARE",
                        title="Missing SecurityMiddleware in Django MIDDLEWARE",
                        severity=Severity.MEDIUM,
                        owasp_category=OWASPCategory.A05.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=1,
                        description="SecurityMiddleware is absent. Security headers (HSTS, X-Content-Type-Options, SSL redirect) are not enforced by Django.",
                        offending_snippet="MIDDLEWARE without SecurityMiddleware",
                        fix="Add 'django.middleware.security.SecurityMiddleware' near the top of MIDDLEWARE.",
                    )
                )

            if not has_csrf:
                self.findings.append(
                    Finding(
                        id="CFG-MISSING-CSRF-MIDDLEWARE",
                        title="Missing CsrfViewMiddleware in Django MIDDLEWARE",
                        severity=Severity.HIGH,
                        owasp_category=OWASPCategory.A01.value,
                        source=FindingSource.CONFIGURATION,
                        file_path=self.file_path,
                        line_number=1,
                        description="CsrfViewMiddleware is missing. POST, PUT, and DELETE forms and API requests are unprotected against Cross-Site Request Forgery.",
                        offending_snippet="MIDDLEWARE without CsrfViewMiddleware",
                        fix="Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE.",
                    )
                )


def scan_configuration_file(file_path: str) -> List[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        tree = ast.parse(code, filename=file_path)
        visitor = ConfigVisitor(file_path, code)
        visitor.visit(tree)
        visitor.finalize()
        return visitor.findings
    except SyntaxError:
        return []
    except Exception:
        return []


def scan_configuration(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    root = Path(repo_path)
    target_names = {"settings.py", "local_settings.py", "production.py", "base.py", "app.py", "config.py", "wsgi.py"}

    for p in root.rglob("*.py"):
        rel_str = str(p.relative_to(root)).replace("\\", "/")
        if "site-packages" in rel_str or ".venv" in rel_str or "node_modules" in rel_str:
            continue
        if p.name in target_names or "settings" in p.name:
            findings.extend(scan_configuration_file(str(p)))

    return findings
