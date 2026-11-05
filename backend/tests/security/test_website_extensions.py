"""Independent limited expansion checks: pure wrappers and synthetic SQL only.

AST extraction executes the checked-in function bodies with explicitly limited
dependencies. These tests do not exercise Django/DRF, sessions, ORM SQL, actual
migrations, transactions, HTTP permissions or concurrent requests.
"""
import ast
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[3]
PGLITE = Path("C:/Users/Ken/ken/CurricuLogic-System/.cache/sql-tests/node_modules/@electric-sql/pglite")


class Denial(Exception):
    def __init__(self, code, message="", *args):
        self.code = code
        super().__init__(message)


class Params(dict):
    def getlist(self, key):
        value = self[key]
        return value if isinstance(value, list) else [value]

    def dict(self):
        return {key: self.getlist(key)[-1] for key in self}


def functions(path, names, dependencies=None):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    selected = [item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name in names]
    if len(selected) != len(names):
        raise AssertionError("Missing reviewed function")
    scope = dict(dependencies or {})
    exec(compile(ast.Module(body=selected, type_ignores=[]), path, "exec"), scope)
    return scope


class IndependentPureExpansionTests(unittest.TestCase):
    def pagination(self):
        return functions("backend/apps/operations/pagination.py",
                         {"query_values", "pagination_values", "report_filters", "page_result"},
                         {"re": re, "date": date, "ApiError": Denial,
                          "SOURCE_STATUSES": {"ALL", "PENDING", "PROCESSING", "AWAITING_REVIEW", "FAILED", "APPROVED", "RETURNED", "REJECTED"}})

    def test_report_filter_rejects_ambiguous_unbounded_and_impossible_inputs(self):
        parse = self.pagination()["report_filters"]
        cases = [{"status": ["ALL", "RETURNED"]}, {"unit_id": "hidden"},
                 {"page": "0"}, {"page": "-1"}, {"page": "1.0"}, {"page": " 1"},
                 {"page": "2147483648"}, {"page_size": "51"}, {"page_size": "01"},
                 {"date_from": "2026-02-29"}, {"date_to": "2026-1-01"},
                 {"date_from": "2026-10-14", "date_to": "2026-10-13"},
                 {"status": "READY"}]
        for params in cases:
            with self.subTest(params=params), self.assertRaises(Denial) as error:
                parse(Params(params), "ALL")
            self.assertEqual(error.exception.code, "INVALID_FILTER")

    def test_valid_leap_dates_role_default_and_page_boundaries(self):
        parse = self.pagination()["report_filters"]
        self.assertEqual(parse(Params(), "AWAITING_REVIEW"),
                         {"page": 1, "page_size": 10, "status": "AWAITING_REVIEW"})
        result = parse(Params(date_from="2024-02-29", date_to="2024-02-29", page="2147483647", page_size="50"), "ALL")
        self.assertEqual(result["date_from"], date(2024, 2, 29))
        self.assertEqual(result["date_to"], date(2024, 2, 29))
        self.assertEqual(result["page_size"], 50)

    def test_pagination_serializes_requested_page_only_and_preserves_count(self):
        class ScopedRows:
            def __init__(self):
                self.slices = []

            def count(self):
                return 23

            def __getitem__(self, selection):
                self.slices.append((selection.start, selection.stop))
                return range(23)[selection]

        rows, serialized = ScopedRows(), []
        def render(value):
            serialized.append(value)
            return {"value": value}

        page = self.pagination()["page_result"](rows, {"page": 3, "page_size": 10}, render)
        self.assertEqual(rows.slices, [(20, 30)])
        self.assertEqual(serialized, [20, 21, 22])
        self.assertEqual((page["count"], page["total_pages"]), (23, 3))

    def test_strict_wrapper_accepts_explicit_nullable_uuid_and_rejects_unknown_or_coerced_text(self):
        class Serializer:
            def to_internal_value(self, data):
                return data  # Deliberately no DRF field-validation claim.

        class CharField:
            def __init__(self, allow_null=False):
                self.allow_null = allow_null

        class ChoiceField(CharField):
            pass

        class UUIDField(CharField):
            pass

        tree = ast.parse((ROOT / "backend/apps/operations/serializers.py").read_text(encoding="utf-8"))
        strict = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "StrictSerializer")
        scope = {"serializers": SimpleNamespace(Serializer=Serializer, CharField=CharField,
                 ChoiceField=ChoiceField, UUIDField=UUIDField, ValidationError=Denial)}
        exec(compile(ast.Module(body=[strict], type_ignores=[]), "StrictSerializer", "exec"), scope)
        wrapper = scope["StrictSerializer"]()
        wrapper.fields = {"unit_id": UUIDField(allow_null=True), "username": CharField()}
        self.assertEqual(wrapper.to_internal_value({"unit_id": None}), {"unit_id": None})
        for payload in [{"unit_id": 1}, {"username": None}, {"username": 15}, {"is_superuser": True}, []]:
            with self.subTest(payload=payload), self.assertRaises(Denial):
                wrapper.to_internal_value(payload)

    def test_actual_session_hash_body_binds_password_version_and_fallback_secret(self):
        tree = ast.parse((ROOT / "backend/apps/accounts/models.py").read_text(encoding="utf-8"))
        user = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "User")
        method = next(item for item in user.body if isinstance(item, ast.FunctionDef) and item.name == "_get_session_auth_hash")
        calls = []
        def limited_hmac(salt, value, secret=None, algorithm=None):
            calls.append((salt, value, secret, algorithm))
            return hmac.new((secret or "synthetic-current-key").encode(), value.encode(), hashlib.sha256)
        scope = {"salted_hmac": limited_hmac}
        exec(compile(ast.Module(body=[method], type_ignores=[]), "session-hash-method", "exec"), scope)
        calculate = scope[method.name]
        first = calculate(SimpleNamespace(password="synthetic-password-hash", permission_version=1))
        changed = calculate(SimpleNamespace(password="synthetic-password-hash", permission_version=2))
        reset = calculate(SimpleNamespace(password="different-synthetic-hash", permission_version=1))
        fallback = calculate(SimpleNamespace(password="synthetic-password-hash", permission_version=1), secret="synthetic-fallback")
        self.assertEqual(len({first, changed, reset, fallback}), 4)
        self.assertEqual(calls[-1][2:], ("synthetic-fallback", "sha256"))
        # This establishes input binding; actual Django fallback/session behavior
        # belongs to the separately authored, currently unavailable API suite.

    def test_admin_projection_does_not_read_or_emit_credential_fields(self):
        class Account:
            id, username, display_name = "account-id", "synthetic-user", "Synthetic User"
            role, is_active, permission_version = "administrator", True, 3

            @property
            def password(self):
                raise AssertionError("Credential field was read")

        project = functions("backend/apps/accounts/services.py", {"admin_user"},
                            {"assignment_ids": lambda _: (None, None)})["admin_user"]
        result = project(Account())
        self.assertEqual(set(result), {"id", "username", "display_name", "role", "is_active", "permission_version", "unit_id", "channel_id"})
        self.assertIsNone(result["unit_id"])
        self.assertIsNone(result["channel_id"])

    def test_identity_logic_locks_organization_first_and_rejects_stale_actor(self):
        presented = SimpleNamespace(pk="actor", organization_id="organization", role="administrator", permission_version=7)
        current = SimpleNamespace(pk="actor", role="administrator", permission_version=7)
        trace = []
        state = {"organization": SimpleNamespace(id="organization"), "actor": current}

        class Manager:
            def __init__(self, kind):
                self.kind = kind

            def select_for_update(self):
                trace.append(self.kind)
                return self

            def filter(self, **values):
                expected = ({"pk": "organization", "active": True} if self.kind == "organization"
                            else {"pk": "actor", "is_active": True, "organization_id": "organization"})
                if values != expected:
                    raise AssertionError("Missing current organization/identity filter")
                return self

            def first(self):
                return state[self.kind]

        lock = functions("backend/apps/scopes/access.py", {"lock_identity"}, {
            "Organization": SimpleNamespace(objects=Manager("organization")),
            "User": SimpleNamespace(objects=Manager("actor")),
            "forbidden": lambda: Denial("ACCESS_DENIED"),
        })["lock_identity"]
        self.assertEqual(lock(presented), (current, state["organization"]))
        self.assertEqual(trace, ["organization", "actor"])
        for changed in [None, SimpleNamespace(role="recipient", permission_version=7),
                        SimpleNamespace(role="administrator", permission_version=8)]:
            state["actor"] = changed
            with self.subTest(changed=changed), self.assertRaises(Denial):
                lock(presented)
        state["actor"], state["organization"] = current, None
        with self.assertRaises(Denial):
            lock(presented)


class IndependentGrantIndexTests(unittest.TestCase):
    def test_declared_partial_indexes_preserve_history_and_block_duplicate_active_grants(self):
        if not shutil.which("node") or not PGLITE.is_dir():
            self.skipTest("Explicitly permitted cached PGlite is unavailable")
        tree = ast.parse((ROOT / "backend/apps/scopes/migrations/0003_preserve_grant_history.py").read_text(encoding="utf-8"))
        indexes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "UniqueConstraint":
                args = {value.arg: value.value for value in node.keywords}
                fields, name = ast.literal_eval(args["fields"]), ast.literal_eval(args["name"])
                condition = args["condition"]
                self.assertIsInstance(condition, ast.Call)
                self.assertEqual([(item.arg, ast.literal_eval(item.value)) for item in condition.keywords], [("active", True)])
                self.assertTrue(all(re.fullmatch("[a-z_]+", value) for value in [name, *fields]))
                indexes.append({"name": name, "fields": fields})
        self.assertEqual(len(indexes), 2)
        # The fixture uses each actual declaration's fields/condition, but it is
        # not Django-generated DDL and intentionally makes no migration claim.
        script = r"""
const fs = require('node:fs');
const library = process.argv[1];
if (JSON.parse(fs.readFileSync(library+'/package.json')).version !== '0.3.14') throw Error('Unexpected package version');
const {PGlite} = require(library+'/dist/index.cjs');
(async()=>{
  const db = new PGlite(); let cases=0;
  for (const [i, spec] of JSON.parse(process.argv[2]).entries()) {
    const table='grant_fixture_'+i;
    const columns=spec.fields.map(name=>'"'+name+'" text NOT NULL').join(',');
    const fields=spec.fields.map(name=>'"'+name+'"').join(',');
    const values=spec.fields.map(name=>"'synthetic_"+name+"'").join(',');
    await db.exec('CREATE TABLE '+table+'('+columns+', active boolean NOT NULL);CREATE UNIQUE INDEX '+spec.name+' ON '+table+'('+fields+') WHERE active');
    await db.exec('INSERT INTO '+table+' VALUES ('+values+',true)'); cases++;
    let denied=false; try { await db.exec('INSERT INTO '+table+' VALUES ('+values+',true)'); } catch(error) {if(error.code!=='23505')throw error;denied=true;}
    if(!denied)throw Error('Duplicate active grant accepted'); cases++;
    await db.exec('UPDATE '+table+' SET active=false;INSERT INTO '+table+' VALUES ('+values+',true);INSERT INTO '+table+' VALUES ('+values+',false)');
    const rows=(await db.query('SELECT active,count(*)::int AS total FROM '+table+' GROUP BY active ORDER BY active')).rows;
    if(JSON.stringify(rows)!==JSON.stringify([{active:false,total:2},{active:true,total:1}]))throw Error('Grant history lost');cases++;
    denied=false;try{await db.exec('ALTER TABLE '+table+' ADD UNIQUE ('+fields+')');}catch(error){if(error.code!=='23505')throw error;denied=true;}
    if(!denied)throw Error('Restoring old uniqueness should fail with preserved history');cases++;
  }
  await db.close();process.stdout.write(JSON.stringify({cases,actual_django_migration:false}));
})().catch(()=>{process.stderr.write('Synthetic index probe failed');process.exitCode=1});
"""
        result = subprocess.run([shutil.which("node"), "-e", script, str(PGLITE), json.dumps(indexes)],
                                capture_output=True, text=True, timeout=30, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"cases": 8, "actual_django_migration": False})


if __name__ == "__main__":
    unittest.main()
