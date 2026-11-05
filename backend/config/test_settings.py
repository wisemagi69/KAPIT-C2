"""Test settings keep PostgreSQL and security middleware enabled."""
import os
from .supabase import require_local_test_context

require_local_test_context(os.environ)
from .settings import *  # noqa: F403

ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]", "testserver"]
# Reduce fixture cost without changing the running website's password hasher.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
# LiveServerTestCase's static handler parses STATIC_URL; unset (None) breaks every request.
STATIC_URL = "/static/"
# Tests keep one connection per request: test-server threads must not hold
# connections open while the disposable test database is destroyed.
DATABASES["default"]["CONN_MAX_AGE"] = 0  # noqa: F405
