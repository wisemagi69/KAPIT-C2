"""Independent negative checks with explicit runtime/ORM test doubles.

No database, service, secret store or network is accessed. Extracted backend
function bodies do not prove Django sessions, transactions, CSRF or SQL locks.
"""
import ast
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as Object
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import local, native_postgres as pg


def extract(path, names, scope):
    nodes = [item for item in ast.parse((ROOT / path).read_text(encoding="utf-8")).body
             if isinstance(item, ast.FunctionDef) and item.name in names]
    if {node.name for node in nodes} != set(names):
        raise AssertionError("Reviewed function is absent")
    for node in nodes:
        node.decorator_list = []  # Transactions are explicitly outside these checks.
    exec(compile(ast.Module(body=nodes, type_ignores=[]), path, "exec"), scope)


class Denial(Exception):
    pass


class IndependentRuntimeChecks(unittest.TestCase):
    def test_alternate_loopback_cannot_pass_ownership_check_then_target_another_service(self):
        for host in ("127.0.0.2", "127.12.34.56", "::1", "::ffff:127.0.0.1"):
            with self.subTest(host=host), patch.dict(os.environ, {"KAPIT_DB_HOST": host}, clear=True), \
                    patch.object(local, "native_module") as module, patch.object(local, "run") as run:
                with self.assertRaises(RuntimeError):
                    local.native_test()
                module.assert_not_called()
                run.assert_not_called()

    def test_managed_environment_keeps_owned_endpoint_and_removes_redirects(self):
        inherited = {"KAPIT_DB_HOST": "localhost", "PGSERVICE": "other", "PGHOST": "external.invalid",
                     "PGOPTIONS": "-c search_path=other", "PGPASSWORD": "synthetic-canary",
                     "DATABASE_URL": "synthetic-canary", "DB_URL": "synthetic-canary"}
        with patch.dict(os.environ, inherited, clear=True):
            result = local.managed_environment()
            self.assertEqual(result["KAPIT_DB_HOST"], "127.0.0.1")
            self.assertEqual(result["KAPIT_DB_PORT"], "55436")
            self.assertFalse(any(key.upper().startswith("PG") for key in result))
            self.assertNotIn("DATABASE_URL", result)
            self.assertNotIn("DB_URL", result)
            self.assertEqual(dict(os.environ), inherited)

    def test_saved_process_identity_blocks_unrecorded_process_even_with_matching_binary(self):
        info = {"binaries": {"directory": str(ROOT / "synthetic-bin")}, "process": None}
        record = {"pid": 1234, "started": 9876}
        identity = {"path": pg.binary(info, "postgres"), "started": 9876}
        with patch.object(pg, "pid_record", return_value=record), patch.object(pg, "process_identity", return_value=identity):
            with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                pg.verify_process(info)
            saved = pg.verify_process(info, new=True)
            self.assertEqual(saved["pid"], 1234)
            info["process"] = saved
            self.assertEqual(pg.verify_process(info), saved)
            info["process"] = {**saved, "pid": 1235}
            with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                pg.verify_process(info)

    def test_connection_proof_rejects_each_unowned_server_dimension(self):
        info = {"process": {"started": 1000}}
        baseline = {"data": str(pg.DATA.resolve()), "port": "55436", "listen": "127.0.0.1",
                    "user": "kapit_m1", "started": 1000, "version": "synthetic-version"}
        for key, value in (("data", str(ROOT / "other")), ("port", "5432"), ("listen", "*"),
                           ("user", "postgres"), ("started", 900)):
            with self.subTest(dimension=key), patch.object(pg, "sql", return_value=json.dumps({**baseline, key: value})):
                with self.assertRaisesRegex(RuntimeError, "NATIVE_DATABASE"):
                    pg.verify_connection(info)


class IndependentBackendChecks(unittest.TestCase):
    def test_password_rejection_never_changes_version_credential_or_audit(self):
        for mode in ("wrong_current", "unchanged", "unsuitable", "revoked_context"):
            with self.subTest(mode=mode):
                actor = Object(id="current-actor", permission_version=7)
                actor.check_password = lambda value: value == " current synthetic password "
                actor.set_password, actor.save = Mock(), Mock()
                scope = {"lock_identity": lambda user: (actor, Object(id="org")), "user_object": Mock(),
                         "ApiError": Denial, "serializers": Object(ValidationError=Denial),
                         "validate_new_password": Mock(), "audit": Object(record=Mock())}
                extract("backend/apps/accounts/services.py", {"change_password"}, scope)
                data = {"current_password": " current synthetic password ", "new_password": " suitable replacement "}
                if mode == "wrong_current":
                    data["current_password"] = "wrong synthetic canary"
                elif mode == "unchanged":
                    data["new_password"] = data["current_password"]
                elif mode == "unsuitable":
                    scope["validate_new_password"].side_effect = Denial("suitability")
                else:
                    scope["user_object"].side_effect = Denial("scope")
                with self.assertRaises(Denial) as error:
                    scope["change_password"](actor, data)
                actor.set_password.assert_not_called()
                actor.save.assert_not_called()
                scope["audit"].record.assert_not_called()
                self.assertEqual(actor.permission_version, 7)
                self.assertNotIn(data["current_password"], str(error.exception))
                self.assertNotIn(data["new_password"], str(error.exception))

    def test_workflow_serializes_only_contract_metadata_without_private_worker_values(self):
        class Rows(list):
            def order_by(self, *args):
                return self

            def select_related(self, *args):
                return self

            def first(self):
                return self[0] if self else None

        stamp = Object(isoformat=lambda: "2026-10-14T00:00:00+00:00")
        revision = Object(revision_no=1, received_at=stamp, processing_state="FAILED", variants=Rows(),
                          jobs=Rows([Object(status="FAILED", attempts=2, error_code="PRIVATE_WORKER_CANARY",
                                            lease_token="PRIVATE_LEASE_CANARY", lease_generation=4)]))
        scope = {"Publication": Object(objects=Mock()), "valid_publication": Mock(),
                 "representative_variant": lambda revision: None,
                 "current_job": lambda revision: revision.jobs[0] if revision.jobs else None}
        extract("backend/apps/reports/workflow.py", {"revision_workflow"}, scope)
        result = scope["revision_workflow"](Object(current_revision_no=1), revision, Object(id="org"))
        self.assertEqual(result, {"revision_no": 1, "is_current": True, "received_at": stamp.isoformat(),
                                  "processing": {"state": "FAILED", "attempts": 2},
                                  "review": {"state": "NOT_READY", "prepared_at": None, "decided_at": None},
                                  "sharing": {"state": "NOT_SHARED", "published_at": None}})
        self.assertNotIn("CANARY", json.dumps(result))
        scope["Publication"].objects.filter.assert_not_called()
        scope["valid_publication"].assert_not_called()

    def test_feed_never_searches_or_serializes_invalid_rows_before_counting(self):
        class Rows:
            def iterator(self, chunk_size):
                self.chunk_size = chunk_size
                for index in range(151):
                    yield Object(id=index, report_id=f"report-{index}", channel_id="channel", published_at=index,
                                 profile="DEMO-REDUCED", valid=index % 3 != 0, projection={"approved": index})

        rows, calls = Rows(), []
        def match(projection, options):
            self.assertNotEqual(projection["approved"] % 3, 0)
            calls.append(projection["approved"])
            return True

        recipient = Object(ceiling="DEMO-REDUCED", expanded=False)
        delivered = []
        scope = {"current_publications": lambda *args, **kwargs: (recipient, rows),
                 "_read_identity": lambda actor, org: (actor, org), "recipient_scope": lambda *args: recipient,
                 "PROFILE_RANK": {"DEMO-REDUCED": 2},
                 "ApiError": Denial,
                 "record_deliveries": lambda actor, org, values: delivered.extend(value.id for value in values),
                 "feed_filters": lambda params: {"page": 10, "page_size": 10},
                 "valid_publication": lambda value, org: value.valid,
                 "matches_projection": match, "serialize_publication": lambda value: {"id": value.id}}
        extract("backend/apps/publications/selectors.py", {"feed", "selected_publications", "filtered_publications"}, scope)
        result = scope["feed"](None, None, "channel", {})
        self.assertEqual(result["count"], 100)
        self.assertEqual(result["total_pages"], 10)
        self.assertEqual(result["results"], [{"id": index} for index in range(14, 0, -1) if index % 3])
        self.assertEqual(delivered, [value["id"] for value in result["results"]])
        self.assertEqual(len(calls), 100)
        self.assertEqual(rows.chunk_size, 100)


if __name__ == "__main__":
    unittest.main()
