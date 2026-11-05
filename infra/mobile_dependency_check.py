"""Explicit project-venv compatibility checks, using memory-only synthetic keys."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest

import jwt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from config.mobile import JWT_ALGORITHM, JWT_ISSUER, JWT_AUDIENCE, JWT_PACKAGE_VERSION


class JwtCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        now = int(time.time())
        self.claims = {"iss": JWT_ISSUER, "aud": JWT_AUDIENCE,
                       "sub": "11111111-1111-4111-8111-111111111111", "iat": now, "nbf": now, "exp": now + 60}

    def decode(self, value, key=None):
        return jwt.decode(value, key or self.key, algorithms=[JWT_ALGORITHM], issuer=JWT_ISSUER,
                          audience=JWT_AUDIENCE, leeway=0,
                          options={"require": ["iss", "aud", "sub", "iat", "nbf", "exp"], "strict_aud": True})

    def test_installed_version_and_fixed_hs256_roundtrip(self):
        self.assertEqual(jwt.__version__, JWT_PACKAGE_VERSION)
        token = jwt.encode(self.claims, self.key, algorithm=JWT_ALGORITHM)
        self.assertTrue(self.decode(token) == self.claims)

    def test_unapproved_algorithm_and_wrong_signing_key_rejected(self):
        for algorithm, key in [("none", None), ("HS384", secrets.token_bytes(48))]:
            token = jwt.encode(self.claims, key, algorithm=algorithm)
            with self.assertRaises(jwt.InvalidAlgorithmError):
                self.decode(token)
        token = jwt.encode(self.claims, self.key, algorithm=JWT_ALGORITHM)
        with self.assertRaises(jwt.InvalidSignatureError):
            self.decode(token, secrets.token_bytes(32))

    def test_wrong_issuer_audience_missing_claim_and_expiry_rejected(self):
        for field, value in [("iss", "wrong"), ("aud", "wrong"), ("aud", [JWT_AUDIENCE]), ("exp", int(time.time()) - 1)]:
            token = jwt.encode({**self.claims, field: value}, self.key, algorithm=JWT_ALGORITHM)
            with self.assertRaises(jwt.InvalidTokenError):
                self.decode(token)
        claims = {key: value for key, value in self.claims.items() if key != "exp"}
        with self.assertRaises(jwt.MissingRequiredClaimError):
            self.decode(jwt.encode(claims, self.key, algorithm=JWT_ALGORITHM))


class InactiveSettingsTests(unittest.TestCase):
    def test_default_missing_invalid_and_valid_mobile_configuration_preserve_web_imports(self):
        script = '''import json,sys
sys.path.insert(0,"backend")
import django
django.setup()
from django.conf import settings
from django.core.checks import run_checks
from django.test import Client
from django.urls import resolve, Resolver404
client=Client(enforce_csrf_checks=True,HTTP_HOST="127.0.0.1")
csrf=client.get("/api/v1/auth/csrf/")
denied=client.post("/api/v1/auth/login/",data="{}",content_type="application/json")
web=client.get("/api/v1/me/",HTTP_AUTHORIZATION="Bearer synthetic-invalid")
try:
    resolve("/api/v1/mobile/auth/challenge/")
    mobile_absent=False
except Resolver404:
    mobile_absent=True
print(json.dumps({"issues":len(run_checks()),"csrf":csrf.status_code==200,"csrf_denied":denied.status_code==403,
    "web_bearer_denied":web.status_code==403,"mobile_absent":mobile_absent,
    "web_session_default":settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]==["rest_framework.authentication.SessionAuthentication"],
    "no_atomic_requests":not settings.DATABASES["default"].get("ATOMIC_REQUESTS",False),
    "mobile_available":settings.KAPIT_MOBILE_AUTH.available,
    "no_mobile_import":not any(name.startswith("apps.accounts.mobile") for name in sys.modules)}))
'''
        base = {name: value for name, value in os.environ.items() if name.upper() in
                {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA"}}
        base.update({"DJANGO_SETTINGS_MODULE": "config.settings", "KAPIT_RUNTIME_CONTEXT": "native",
            "KAPIT_SECRET_KEY": secrets.token_urlsafe(64),
            "KAPIT_SOURCE_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
            "KAPIT_DB_PASSWORD": secrets.token_urlsafe(32)})
        valid = secrets.token_urlsafe(32)
        for environment, expected in [({}, False), ({"KAPIT_MOBILE_ENABLED": "1"}, False),
            ({"KAPIT_MOBILE_ENABLED": "1", "KAPIT_MOBILE_SIGNING_KEY": "invalid"}, False),
            ({"KAPIT_MOBILE_ENABLED": "1", "KAPIT_MOBILE_SIGNING_KEY": valid}, True)]:
            process = subprocess.run([sys.executable, "-B", "-c", script], cwd=ROOT, env={**base, **environment},
                                     capture_output=True, text=True, timeout=30)
            self.assertTrue(process.returncode == 0, "Synthetic settings subprocess failed; private output withheld.")
            try:
                result = json.loads(process.stdout)
            except ValueError:
                self.fail("Settings subprocess returned invalid metadata; private output withheld.")
            self.assertTrue(result["issues"] == 0 and result["mobile_available"] is expected)
            self.assertTrue(all(value is True for key, value in result.items() if key not in {"issues", "mobile_available"}))


if __name__ == "__main__":
    unittest.main()
