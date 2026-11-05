"""Explicit, isolated browser acceptance runner; never adopts a test database."""
import os
from pathlib import Path
import sys
from types import MethodType

from django.test.runner import DiscoverRunner


TEST_DATABASE = "test_kapit_m1"
ADVISORY_LOCK = 746397301
PRESERVE_DATABASE = False
ACTIVE_DATABASE_LEASE = None


def preserve_database():
    global PRESERVE_DATABASE
    PRESERVE_DATABASE = True


class BrowserGuardError(RuntimeError):
    """Only fixed metadata codes may cross the harness boundary."""


def require_target(config, environment, *, running_test=False):
    expected = TEST_DATABASE if running_test else "kapit_m1"
    if environment.get("DJANGO_SETTINGS_MODULE") != "config.test_settings":
        raise BrowserGuardError("BROWSER_SETTINGS_DENIED")
    if environment.get("KAPIT_RUNTIME_CONTEXT", "native") != "native":
        raise BrowserGuardError("BROWSER_CONTEXT_DENIED")
    if any(key.upper().startswith("PG") or key in {"DATABASE_URL", "DB_URL"} for key in environment):
        raise BrowserGuardError("BROWSER_ENVIRONMENT_DENIED")
    if (config.get("ENGINE") != "django.db.backends.postgresql"
            or config.get("NAME") != expected or config.get("USER") != "kapit_m1"
            or config.get("HOST") != "127.0.0.1" or str(config.get("PORT")) != "55436"
            or config.get("TEST", {}).get("NAME") != TEST_DATABASE
            or config.get("TEST", {}).get("MIRROR")
            or set(config.get("OPTIONS", {})) - {"connect_timeout"}):
        raise BrowserGuardError("BROWSER_DATABASE_DENIED")


class DatabaseLease:
    """Hold a separate autocommit connection from preflight through destruction."""

    def __init__(self, connection):
        self.connection = connection
        self.locked = False
        self.owned_oid = None

    def acquire(self):
        try:
            self.connection.ensure_connection()
            self.connection.set_autocommit(True)
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT pg_try_advisory_lock(%s)", [ADVISORY_LOCK])
                self.locked = cursor.fetchone()[0] is True
            if not self.locked:
                raise BrowserGuardError("BROWSER_DATABASE_BUSY")
            if self.current_oid() is not None:
                raise BrowserGuardError("BROWSER_DATABASE_EXISTS")
        except BrowserGuardError:
            self.close()
            raise
        except Exception:
            self.close()
            raise BrowserGuardError("BROWSER_DATABASE_UNAVAILABLE") from None

    def current_oid(self):
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT oid FROM pg_database WHERE datname = %s", [TEST_DATABASE])
                result = cursor.fetchone()
            return result[0] if result else None
        except Exception:
            raise BrowserGuardError("BROWSER_DATABASE_IDENTITY_UNAVAILABLE") from None

    def create(self):
        if not self.locked or self.owned_oid is not None:
            raise BrowserGuardError("BROWSER_DATABASE_OWNERSHIP")
        try:
            # A concurrent non-cooperating creator can still win this statement.
            # Any failure propagates; there is no prompt, DROP, or adoption path.
            with self.connection.cursor() as cursor:
                cursor.execute('CREATE DATABASE "test_kapit_m1"')
            self.owned_oid = self.current_oid()
            if self.owned_oid is None:
                raise BrowserGuardError("BROWSER_DATABASE_OWNERSHIP")
        except Exception:
            raise BrowserGuardError("BROWSER_DATABASE_CREATE_FAILED") from None
        return TEST_DATABASE

    def assert_owned(self):
        if not self.locked or self.owned_oid is None or self.current_oid() != self.owned_oid:
            raise BrowserGuardError("BROWSER_DATABASE_OWNERSHIP")

    def close(self):
        # Closing the session releases its advisory lock even after an error.
        try:
            self.connection.close()
        except Exception:
            raise BrowserGuardError("BROWSER_DATABASE_RELEASE_FAILED") from None
        finally:
            self.locked = False


class BrowserAcceptanceRunner(DiscoverRunner):
    def __init__(self, *args, **kwargs):
        if kwargs.get("keepdb") or kwargs.get("parallel", 0) not in {0, 1} or kwargs.get("interactive", True) is False:
            raise BrowserGuardError("BROWSER_RUNNER_OPTIONS_DENIED")
        super().__init__(*args, **kwargs)
        self._browser_lease = None

    def run_tests(self, test_labels, **kwargs):
        if list(test_labels) not in [["tests"], ["tests.browser_acceptance"]]:
            raise BrowserGuardError("BROWSER_TEST_LABELS_DENIED")
        return super().run_tests(test_labels, **kwargs)

    def setup_databases(self, **kwargs):
        global ACTIVE_DATABASE_LEASE
        from django.db import connections
        if set(connections) != {"default"}:
            raise BrowserGuardError("BROWSER_DATABASE_ALIASES_DENIED")
        connection = connections["default"]
        require_target(connection.settings_dict, os.environ)
        root = Path(__file__).resolve().parents[2]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from infra.native_postgres import status
        status(require_running=True)
        maintenance = connection.copy(alias="browser_guard")
        maintenance.settings_dict["NAME"] = "postgres"
        lease = DatabaseLease(maintenance)
        lease.acquire()
        self._browser_lease = lease
        ACTIVE_DATABASE_LEASE = lease
        creation = connection.creation
        original_create = creation._create_test_db
        self._browser_destroy = creation._destroy_test_db
        self._browser_creation = creation

        def destroy_only_owned(_creation, test_database_name, verbosity, *args, **options):
            if PRESERVE_DATABASE or test_database_name != TEST_DATABASE:
                raise BrowserGuardError("BROWSER_DATABASE_DESTRUCTION_DENIED")
            lease.assert_owned()
            return self._browser_destroy(test_database_name, verbosity, *args, **options)

        creation._destroy_test_db = MethodType(destroy_only_owned, creation)

        def create_only_owned(_creation, verbosity, autoclobber, keepdb=False):
            if keepdb or _creation._get_test_db_name() != TEST_DATABASE:
                raise BrowserGuardError("BROWSER_DATABASE_CREATE_DENIED")
            return lease.create()

        creation._create_test_db = MethodType(create_only_owned, creation)
        try:
            return super().setup_databases(**kwargs)
        except BaseException:
            # Django hasn't returned old_config when migration setup fails.
            # Clean up only our successfully created, still-identical database.
            try:
                if lease.owned_oid is not None and connection.settings_dict["NAME"] == TEST_DATABASE:
                    lease.assert_owned()
                    creation.destroy_test_db("kapit_m1", verbosity=0, keepdb=False)
            except Exception:
                raise BrowserGuardError("BROWSER_DATABASE_CLEANUP_FAILED") from None
            finally:
                creation._destroy_test_db = self._browser_destroy
                ACTIVE_DATABASE_LEASE = None
                lease.close()
            raise BrowserGuardError("BROWSER_DATABASE_SETUP_FAILED") from None
        finally:
            creation._create_test_db = original_create

    def teardown_databases(self, old_config, **kwargs):
        global ACTIVE_DATABASE_LEASE
        lease = self._browser_lease
        if lease is None:
            raise BrowserGuardError("BROWSER_DATABASE_OWNERSHIP")
        try:
            if PRESERVE_DATABASE:
                raise BrowserGuardError("BROWSER_CLEANUP_UNSAFE_DATABASE_RETAINED")
            lease.assert_owned()
            return super().teardown_databases(old_config, **kwargs)
        except BrowserGuardError:
            raise
        except Exception:
            raise BrowserGuardError("BROWSER_DATABASE_TEARDOWN_FAILED") from None
        finally:
            self._browser_creation._destroy_test_db = self._browser_destroy
            ACTIVE_DATABASE_LEASE = None
            lease.close()
