import tempfile
from pathlib import Path
from repoguard.core.models import OWASPCategory, Severity
from repoguard.static.config_checker import scan_configuration_file


def test_django_settings_vulnerabilities():
    content = """
DEBUG = True
SECRET_KEY = "django-insecure-super-secret-key-12345"
ALLOWED_HOSTS = ["*"]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "prod_db",
        "USER": "admin",
        "PASSWORD": "PlaintextPassword123!",
    }
}
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
CORS_ALLOW_ALL_ORIGINS = True
"""
    with tempfile.NamedTemporaryFile("w", suffix="settings.py", delete=False) as f:
        f.write(content)
        tmp_name = f.name

    try:
        findings = scan_configuration_file(tmp_name)
        finding_ids = [f.id for f in findings]
        titles = [f.title for f in findings]

        assert any("DEBUG" in t for t in titles)
        assert any("ALLOWED_HOSTS" in t for t in titles)
        assert any("SECRET_KEY" in t for t in titles)
        assert any("database password" in t for t in titles)
        assert any("SecurityMiddleware" in t for t in titles)
        assert any("CsrfViewMiddleware" in t for t in titles)
        assert any("SESSION_COOKIE_SECURE" in t for t in titles)
        assert any("CSRF_COOKIE_SECURE" in t for t in titles)
        assert any("CORS" in t for t in titles)

        crit_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit_findings) >= 2
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def test_flask_debug_run():
    content = """
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "ok"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
"""
    with tempfile.NamedTemporaryFile("w", suffix="app.py", delete=False) as f:
        f.write(content)
        tmp_name = f.name

    try:
        findings = scan_configuration_file(tmp_name)
        assert any("Flask debug mode" in f.title for f in findings)
    finally:
        Path(tmp_name).unlink(missing_ok=True)
