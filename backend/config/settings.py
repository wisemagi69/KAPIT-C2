"""Fail-closed settings for the approved synthetic loopback demonstration."""
import base64
import json
import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from .runtime_boundary import boundary

try:
    _runtime = boundary()
except RuntimeError as error:
    raise ImproperlyConfigured(str(error)) from None

BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BASE_DIR.parent
SECRET_FILE = Path(os.environ.get("KAPIT_SECRETS_FILE", PROJECT_DIR / ".cache/m1-runtime/secrets.json"))


def load_local_secrets():
    if _runtime.context == "hosted-demo":
        # Hosted keys come only from the host environment, never a local file.
        return {}
    if all(os.environ.get(name) for name in ("KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_DB_PASSWORD")):
        return {}
    try:
        data = json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ImproperlyConfigured("Local secrets are unavailable. Run python infra/local.py init.") from None
    if not isinstance(data, dict):
        raise ImproperlyConfigured("Local secrets have an invalid format.")
    return data


_secrets = load_local_secrets()


def required_secret(name):
    value = os.environ.get(name, _secrets.get(name))
    if not isinstance(value, str) or not value:
        raise ImproperlyConfigured(f"Required local setting {name} is unavailable.")
    return value


SECRET_KEY = required_secret("KAPIT_SECRET_KEY")
if len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("Local session signing key is invalid.")
KAPIT_SOURCE_KEY = required_secret("KAPIT_SOURCE_KEY")
try:
    if len(base64.b64decode(KAPIT_SOURCE_KEY.encode("ascii"), altchars=b"-_", validate=True)) != 32:
        raise ValueError
except (ValueError, UnicodeError):
    raise ImproperlyConfigured("Local source encryption key is invalid.") from None

DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "apps.accounts",
    "apps.scopes",
    "apps.reports",
    "apps.review",
    "apps.publications",
    "apps.audit",
    "apps.operations",
]
MIDDLEWARE = [
    "config.middleware.NoStoreSecurityMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = []
WSGI_APPLICATION = "config.wsgi.application"
AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "kapit_m1",
        "USER": "kapit_m1",
        "PASSWORD": "" if _runtime.context == "hosted-demo" else required_secret("KAPIT_DB_PASSWORD"),
        "HOST": _runtime.db_host,
        "PORT": _runtime.db_port,
        # infra/server.py serves from a fixed set of worker threads, so each
        # keeps at most one connection; health checks retire broken ones.
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"connect_timeout": 5},
        "TEST": {"NAME": "test_kapit_m1"},
    }
}
if _runtime.context == "supabase-m1":
    from .supabase import database_settings
    DATABASES = {"default": database_settings()}
if _runtime.context == "hosted-demo":
    from .hosted import database_settings as hosted_database_settings, web_settings
    DATABASES = {"default": hosted_database_settings()}
# Configuration preparation only. TASK-063 owns later route activation; invalid
# or absent mobile configuration cannot break the accepted web session routes.
from .mobile import load_mobile_config
KAPIT_MOBILE_AUTH = load_mobile_config(
    os.environ, django_secret=SECRET_KEY, source_key=KAPIT_SOURCE_KEY,
    database_password=DATABASES["default"]["PASSWORD"],
)
USE_TZ = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-us"
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "EXCEPTION_HANDLER": "apps.operations.errors.api_exception_handler",
}
CSRF_FAILURE_VIEW = "config.errors.csrf_failure"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_AGE = 60 * 60
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = False
# HTTP loopback only. A future HTTPS deployment needs a separately approved
# configuration with Secure cookies and transport security.
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
if _runtime.context == "hosted-demo":
    # Public HTTPS demonstration behind Render's TLS proxy and Vercel's /api rewrite.
    _web = web_settings()
    ALLOWED_HOSTS = _web["ALLOWED_HOSTS"]
    CSRF_TRUSTED_ORIGINS = _web["CSRF_TRUSTED_ORIGINS"]
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 86400
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 20 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 0
DATA_UPLOAD_MAX_NUMBER_FIELDS = 30
APPEND_SLASH = False
WEB_DIST_DIR = PROJECT_DIR / "web/dist"
# No request bodies, exception text, tracebacks, credentials or tokens are
# emitted. Business audit events are written by explicit backend services.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"discard": {"class": "logging.NullHandler"}},
    "root": {"handlers": ["discard"], "level": "WARNING"},
    "loggers": {
        "django": {"handlers": ["discard"], "propagate": False},
        "django.server": {"handlers": ["discard"], "propagate": False},
        "django.request": {"handlers": ["discard"], "propagate": False},
        "django.security": {"handlers": ["discard"], "propagate": False},
    },
}
