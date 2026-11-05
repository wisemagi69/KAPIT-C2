"""Pure real-crypto checks and separately opted-in guarded archive/restore cohort.

No plaintext fixture values are rendered in assertion diagnostics. The optional
native test is parent-executed only; default discovery never dumps/restores.
"""
from contextlib import contextmanager
from dataclasses import replace, fields
from datetime import datetime, timedelta, timezone
import base64
import copy
import hashlib
import json
import os
import secrets
import unittest
from unittest.mock import patch
import uuid

from cryptography.fernet import Fernet
from apps.operations import evidence_recovery as recovery
from tests.m4.test_evidence_decoder import png, jpeg, chunk, manifest as manifest_fixture

NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)


def public_recovery_receipt(result):
    """Validate the closed adapter aggregate before any captured-log output."""
    invalid = {"schema": 1, "status": "UNAVAILABLE", "code": "INVALID_RECOVERY_RECEIPT"}
    try:
        enums = {"status": {"UNAVAILABLE", "ENCRYPTED_EVIDENCE_ARCHIVE_RECOVERY_VERIFIED"},
                 "scope": {"DISPOSABLE_TEST_COHORT"}, "application": {"CLOSED"},
                 "native_validation": {"NOT_PROVEN_BY_THIS_TEST"}, "current_delivery": {"NOT_EVALUATED"},
                 "cleanup": {"NOT_STARTED", "STOPPED_VERIFIED", "STOP_UNCONFIRMED"}}
        booleans = {"source_preserved", "retained_preserved", "private_files_preserved", "archives_preserved", "fixture_key_preserved"}
        required = {"schema", "phases", "negative_cases"} | set(enums) | booleans
        recovery.require(type(result) is dict and required <= set(result) <= required | {"code", "summary"})
        recovery.require(type(result["schema"]) is int and result["schema"] == 1)
        for key, values in enums.items():
            recovery.require(type(result[key]) is str and result[key] in values)
        recovery.require(all(type(result[key]) is bool for key in booleans))
        if "code" in result:
            recovery.require(type(result["code"]) is str and result["code"] in {
                "PHOTO_EXPLICIT_OPT_IN_REQUIRED", "RESERVATION_REQUIRED", "GUARDED_TEST_COHORT_REQUIRED",
                "PHOTO_RECOVERY_UNAVAILABLE", "CHILD_STOP_UNCONFIRMED", "FINAL_PRESERVATION_UNAVAILABLE",
                "DISPOSABLE_ENCRYPTED_EVIDENCE_VERIFIED"})
        phases = {"LEASED_SOURCE_AND_PRESERVATION_CAPTURED", "FRESH_PRIVATE_TEST_ARCHIVE_VERIFIED",
                  "FRESH_CHILD_RESTORED_SNAPSHOT_EQUAL", "RESTORED_CIPHERTEXT_DECRYPTED_AND_BOUND"}
        negatives = {"OWNED_RECOVERY_KEY_FILE_MISSING", "WRONG_KEY_RESTORED_EVIDENCE_DENIED",
                     "REENCRYPTED_CAPTURE_BINDING_DENIED", "REVISION_BINDING_DENIED", "PROVENANCE_BINDING_DENIED",
                     "SWAPPED_VALIDATION_SOURCE_DENIED", "TAMPERED_DERIVATIVE_DENIED"}
        for key, allowed in (("phases", phases), ("negative_cases", negatives)):
            recovery.require(type(result[key]) is list and len(result[key]) <= len(allowed)
                             and all(type(v) is str and v in allowed for v in result[key])
                             and len(set(result[key])) == len(result[key]))
        if "summary" in result:
            summary = result["summary"]
            counts = set(recovery.RecoverySummary().__dict__)
            recovery.require(type(summary) is dict and set(summary) == counts | {"integrity", "current_delivery", "native_validation"})
            recovery.require(all(type(summary[key]) is int and 0 < summary[key] <= 100 for key in counts))
            recovery.require(summary["integrity"] == "VERIFIED" and summary["current_delivery"] == "NOT_EVALUATED"
                             and summary["native_validation"] == "NOT_PROVEN_BY_THIS_TEST")
        # Return a deep fresh JSON copy, never an arbitrary object's repr.
        return json.loads(json.dumps(result, sort_keys=True, allow_nan=False))
    except Exception:
        return invalid


def fresh_manifest(now):
    value = manifest_fixture()
    value.update(created_at=now.isoformat(), valid_until=(now + timedelta(hours=12)).isoformat(),
                 last_successful_update_check_at=(now - timedelta(minutes=1)).isoformat(),
                 daily_signed_at=(now - timedelta(hours=1)).isoformat())
    for item in value["signature_files"]:
        item["signed_at"] = (now - timedelta(hours=1)).isoformat()
    value["signature_generation"] = hashlib.sha256(recovery.canonical(value["signature_files"])).hexdigest()
    return value


def capture(now, located=True):
    return {"version": 1, "captured_at": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "location": {"latitude_e7": 100, "longitude_e7": -200, "accuracy_mm": 3000,
                         "fix_at": (now - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                         "age_ms": 1000, "mock": True} if located else None}


def original_fixture(key, *, metadata=None, now=NOW, org=None):
    org = org or str(uuid.uuid4())
    ident, actor, revision, operation = (str(uuid.uuid4()) for _ in range(4))
    data = jpeg() if metadata is not None else png()
    media = "image/jpeg" if metadata is not None else "image/png"
    purpose = "private-evidence-capture-v1" if metadata is not None else "private-evidence-v1"
    envelope = {"purpose": purpose, "id": ident, "actor_id": actor, "revision_id": revision,
                "operation_id": operation, "media_type": media, "filename": "capture.jpg" if metadata else "legacy.png",
                "bytes_base64": base64.b64encode(data).decode("ascii")}
    request = {"purpose": purpose, "actor_id": actor, "revision_id": revision, "media_type": media,
               "filename": envelope["filename"], "bytes_sha256": hashlib.sha256(data).hexdigest()}
    if metadata is not None:
        envelope["capture"] = metadata
        request["capture"] = metadata
    record = recovery.OriginalRecord(ident, org, revision, actor, operation, recovery.digest(request),
        key.encrypt(recovery.canonical(envelope)), "local-fernet-v1", media, len(data), 1, "QUARANTINED",
        "DECODER_REQUIRED", now, org, org, org, actor, actor)
    return record, envelope, data


def validation_fixture(key, original, *, now=NOW, success=True):
    binding = recovery.verify_original(original, decrypt_bytes=key.decrypt)
    ident, actor, operation = (str(uuid.uuid4()) for _ in range(3))
    completed = now + timedelta(seconds=1)
    manifest = fresh_manifest(now)
    parsed = recovery.parse_manifest(recovery.canonical(manifest), now=completed)
    request = {"purpose": "private-evidence-validation-v1", "actor_id": actor, "evidence_id": original.id,
               "original_request_hash": original.request_hash, "input_sha256": binding.input_sha256,
               "manifest_hash": parsed.manifest_hash}
    code = "VALIDATION_COMPLETE" if success else "ISOLATION_UNAVAILABLE"
    provenance = {"purpose": "private-evidence-validation-provenance-v1", "validation_id": ident,
        "evidence_id": original.id, "organization_id": original.organization_id, "revision_id": original.revision_id,
        "actor_id": actor, "operation_id": operation, "request_hash": recovery.digest(request),
        "input_sha256": binding.input_sha256, "manifest_hash": parsed.manifest_hash,
        "signature_generation": parsed.signature_generation, "manifest": manifest,
        "code": code, "steps": list(recovery.STEPS) if success else [], "completed_at": completed.isoformat()}
    data = png()
    derivative = {"purpose": "private-evidence-derivative-v1", "validation_id": ident, "evidence_id": original.id,
        "organization_id": original.organization_id, "revision_id": original.revision_id,
        "manifest_hash": parsed.manifest_hash, "signature_generation": parsed.signature_generation,
        "input_sha256": binding.input_sha256, "media_type": "image/png", "width": 1, "height": 1,
        "frames": 1, "bytes_sha256": hashlib.sha256(data).hexdigest(), "bytes_base64": base64.b64encode(data).decode("ascii")}
    row = recovery.ValidationRecord(ident, original.organization_id, original.id, actor, operation,
        recovery.digest(request), parsed.manifest_hash, parsed.signature_generation, binding.input_sha256,
        "VALIDATED_PRIVATE" if success else "QUARANTINED", code, completed + timedelta(milliseconds=1),
        completed if success else None, parsed.expires_at if success else None,
        key.encrypt(recovery.canonical(provenance)), key.encrypt(recovery.canonical(derivative)) if success else None,
        hashlib.sha256(data).hexdigest() if success else None, len(data) if success else None,
        1 if success else None, 1 if success else None, "local-fernet-v1", original.organization_id)
    return row, provenance, derivative, data


class Cursor:
    def __init__(self, database): self.db, self.rows = database, []
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def execute(self, sql, args=()):
        self.db.queries.append(sql)
        if not sql.startswith(("SELECT ", "SHOW ")): raise AssertionError("Read-only SQL required")
        if sql == "SHOW transaction_read_only": self.rows = [(self.db.readonly,)]
        elif sql == "SHOW transaction_isolation": self.rows = [(self.db.isolation,)]
        elif sql.startswith("SELECT id FROM"): self.rows = [(x,) for x in self.db.originals][:101]
        elif sql.startswith("SELECT id,evidence_id"): self.rows = [(x.id, x.evidence_id) for x in self.db.validations.values()][:101]
        elif "octet_length(payload_ciphertext)" in sql:
            self.rows = [(len(self.db.originals[args[0]].payload_ciphertext),)]
        elif "octet_length(provenance_ciphertext)" in sql:
            x = self.db.validations[args[0]]
            self.rows = [(len(x.provenance_ciphertext), len(x.derivative_ciphertext) if x.derivative_ciphertext else None)]
        else:
            x = (self.db.originals if "FROM operations_privateevidence e " in sql else self.db.validations)[args[0]]
            self.rows = [tuple(getattr(x, f.name) for f in fields(x))]
    def fetchone(self): return self.rows.pop(0) if self.rows else None
    def fetchall(self): result, self.rows = self.rows, []; return result


class Database:
    def __init__(self, originals, validations=()):
        self.originals = {x.id: x for x in originals}
        self.validations = {x.id: x for x in validations}
        self.readonly, self.isolation, self.queries = "on", "repeatable read", []
    def cursor(self): return Cursor(self)


class EvidenceRecoveryPureTests(unittest.TestCase):
    def setUp(self):
        self.key = Fernet(Fernet.generate_key())
        self.original, self.envelope, self.data = original_fixture(self.key, metadata=capture(NOW))
        self.binding = recovery.verify_original(self.original, decrypt_bytes=self.key.decrypt)
        self.validation, self.provenance, self.derivative, self.png = validation_fixture(self.key, self.original)

    def reject(self, call):
        with self.assertRaises(recovery.RecoveryError) as result: call()
        self.assertTrue(str(result.exception) == "RESTORED_EVIDENCE_INTEGRITY", "Fixed denial required")

    def encrypted(self, value): return self.key.encrypt(recovery.canonical(value))

    def test_legacy_and_located_and_explicit_null_capture_recover_exact_bytes(self):
        for metadata in (None, capture(NOW), capture(NOW, False)):
            row, _, data = original_fixture(self.key, metadata=metadata)
            binding = recovery.verify_original(row, decrypt_bytes=self.key.decrypt)
            self.assertTrue(binding.data == data, "Original bytes must recover exactly")
            self.assertTrue(binding.capture_json == (None if metadata is None else recovery.canonical(metadata)), "Capture binding must recover exactly")

    def test_actual_fernet_wrong_key_and_malformed_ciphertext_are_fixed_denials(self):
        wrong = Fernet(Fernet.generate_key())
        self.reject(lambda: recovery.verify_original(self.original, decrypt_bytes=wrong.decrypt))
        for payload in (b"", b"invalid", b"x" * (recovery.MAX_CIPHER + 1)):
            self.reject(lambda: recovery.verify_original(replace(self.original, payload_ciphertext=payload), decrypt_bytes=self.key.decrypt))

    def test_original_row_identity_org_media_slot_and_key_mismatch(self):
        for changes in ({"id": str(uuid.uuid4())}, {"operation_id": str(uuid.uuid4())},
                {"revision_organization_id": str(uuid.uuid4())}, {"uploader_organization_id": None},
                {"revision_submitted_by_id": str(uuid.uuid4())}, {"report_author_id": str(uuid.uuid4())},
                {"report_organization_id": str(uuid.uuid4())}, {"slot": True}, {"slot": 3},
                {"byte_size": True}, {"byte_size": self.original.byte_size + 1}, {"key_id": "unknown"},
                {"state": "VALIDATED_PRIVATE"}, {"media_type": "image/png"}, {"id": "INVALID"}):
            self.reject(lambda: recovery.verify_original(replace(self.original, **changes), decrypt_bytes=self.key.decrypt))

    def test_reencrypted_coordinate_changes_fail_request_hash_binding(self):
        value = copy.deepcopy(self.envelope)
        value["capture"]["location"]["latitude_e7"] += 1
        self.reject(lambda: recovery.verify_original(replace(self.original, payload_ciphertext=self.encrypted(value)), decrypt_bytes=self.key.decrypt))

    def test_original_exact_schema_duplicate_depth_float_size_and_base64_fail_closed(self):
        for name, val in (("purpose", "unknown"), ("bytes_base64", "AAAA\n"), ("filename", ""), ("extra", True),
                          ("capture", None), ("capture", {"nested": [[[[[[[[[[1]]]]]]]]]]})):
            value = copy.deepcopy(self.envelope); value[name] = val
            self.reject(lambda: recovery.verify_original(replace(self.original, payload_ciphertext=self.encrypted(value)), decrypt_bytes=self.key.decrypt))
        for raw in (b'{"purpose":"private-evidence-v1","purpose":"private-evidence-v1"}', b'{"x":NaN}', b'{"x":1.0}', b"[" * 2000):
            self.reject(lambda: recovery.verify_original(replace(self.original, payload_ciphertext=self.key.encrypt(raw)), decrypt_bytes=self.key.decrypt))
        self.reject(lambda: recovery.strict_json(b"x" * 20, 10))

    def test_success_provenance_and_normalized_png_recover_without_current_manifest(self):
        result = recovery.verify_validation(self.validation, self.binding, decrypt_bytes=self.key.decrypt)
        self.assertTrue(result.derivative == self.png, "Prepared bytes must recover exactly")
        self.assertTrue(result.validation_id == self.validation.id, "Private binding must remain exact")
        # NOW is historical: verification intentionally does not read wall time/current_tools.
        self.assertTrue(self.validation.expires_at < NOW + timedelta(days=30), "Historical recovery must not renew expiry")

    def test_failure_attempt_requires_absent_derivative_and_known_state_code(self):
        row, _, _, _ = validation_fixture(self.key, self.original, success=False)
        self.assertTrue(recovery.verify_validation(row, self.binding, decrypt_bytes=self.key.decrypt).derivative is None)
        for changes in ({"derivative_ciphertext": self.validation.derivative_ciphertext}, {"width": 1},
                        {"code": "NEW_UNKNOWN_CODE"}, {"state": "VALIDATED_PRIVATE"}):
            self.reject(lambda: recovery.verify_validation(replace(row, **changes), self.binding, decrypt_bytes=self.key.decrypt))

    def test_validation_cross_row_hash_org_actor_manifest_generation_and_time_swaps(self):
        for changes in ({"organization_id": str(uuid.uuid4())}, {"validator_organization_id": str(uuid.uuid4())},
                {"validated_by_id": str(uuid.uuid4())}, {"evidence_id": str(uuid.uuid4())}, {"id": str(uuid.uuid4())},
                {"input_sha256": "f" * 64}, {"manifest_hash": "f" * 64}, {"signature_generation": "f" * 64},
                {"key_id": "unknown"}, {"width": True}, {"validated_at": NOW - timedelta(seconds=1)},
                {"expires_at": NOW + timedelta(days=4)}, {"created_at": NOW.replace(tzinfo=None)}):
            self.reject(lambda: recovery.verify_validation(replace(self.validation, **changes), self.binding, decrypt_bytes=self.key.decrypt))

    def test_reencrypted_provenance_extra_wrong_steps_and_manifest_are_denied(self):
        for key, value in (("steps", list(reversed(recovery.STEPS))), ("steps", ["ORIGINAL_SCAN_CLEAN"]),
                           ("manifest", {"synthetic_tool_declaration": 1}), ("extra", True), ("operation_id", str(uuid.uuid4()))):
            changed = copy.deepcopy(self.provenance); changed[key] = value
            self.reject(lambda: recovery.verify_validation(replace(self.validation, provenance_ciphertext=self.encrypted(changed)), self.binding, decrypt_bytes=self.key.decrypt))

    def test_derivative_exact_shape_bool_frames_changed_bytes_dimensions_and_metadata(self):
        for key, value in (("frames", True), ("frames", 2), ("revision_id", str(uuid.uuid4())),
                           ("bytes_base64", base64.b64encode(self.png + b"tail").decode()), ("width", 2),
                           ("media_type", "image/jpeg"), ("extra", True)):
            changed = copy.deepcopy(self.derivative); changed[key] = value
            self.reject(lambda: recovery.verify_validation(replace(self.validation, derivative_ciphertext=self.encrypted(changed)), self.binding, decrypt_bytes=self.key.decrypt))

    def test_matching_derivative_size_and_hash_still_reject_metadata_or_crc_damage(self):
        for data in (png(extras=(chunk(b"tEXt", b"private=fixture"),)), self.png.replace(b"IDAT", b"JDAT", 1)):
            # Rebind row/envelope size+hash: refusal must reach the normalized
            # container policy rather than a prior checksum mismatch.
            changed = copy.deepcopy(self.derivative)
            changed["bytes_base64"] = base64.b64encode(data).decode("ascii")
            changed["bytes_sha256"] = hashlib.sha256(data).hexdigest()
            row = replace(self.validation, derivative_ciphertext=self.encrypted(changed),
                          derivative_sha256=changed["bytes_sha256"], derivative_size=len(data))
            self.reject(lambda: recovery.verify_validation(row, self.binding, decrypt_bytes=self.key.decrypt))

    def test_record_readers_suppress_sql_errors_and_refuse_wrong_snapshot(self):
        broken = Database([])
        with patch.object(broken, "cursor", side_effect=RuntimeError("PRIVATE_FIXTURE_SQL")):
            self.reject(lambda: recovery.read_original(broken, self.original.id))
            self.reject(lambda: recovery.read_validation(broken, self.validation.id))
        broken.readonly = "off"
        self.reject(lambda: recovery.read_original(broken, self.original.id))
        self.reject(lambda: recovery.read_validation(broken, self.validation.id))

    def cohort(self):
        legacy, _, data = original_fixture(self.key)
        null, _, null_data = original_fixture(self.key, metadata=capture(NOW, False))
        fail, _, _, _ = validation_fixture(self.key, null, success=False)
        expected = {legacy.id: recovery.ExpectedEvidence(data, None),
                    null.id: recovery.ExpectedEvidence(null_data, recovery.canonical(capture(NOW, False))),
                    self.original.id: recovery.ExpectedEvidence(self.data, recovery.canonical(capture(NOW)), ((self.validation.id, self.png),))}
        return Database([legacy, null, self.original], [self.validation, fail]), expected

    def test_streamed_restored_rows_exact_expected_cohort_and_safe_summary(self):
        db, expected = self.cohort()
        result = recovery.verify_restored_evidence(db, decrypt_bytes=self.key.decrypt, expected_cohort=expected)
        self.assertTrue(result.originals_verified == 3 and result.derivatives_verified == 1 and result.provenance_verified == 2)
        self.assertTrue(all("SELECT " in q or q.startswith("SHOW ") for q in db.queries))
        self.assertTrue(set(result.as_dict()) == {"originals_verified", "legacy_verified", "capture_verified", "located_verified",
            "derivatives_verified", "provenance_verified", "integrity", "current_delivery", "native_validation"})
        self.assertTrue("private" in repr(self.binding) and self.original.id not in repr(self.binding), "Private binding representation must redact")

    def test_requires_readonly_repeatable_snapshot_before_ciphertext_queries(self):
        for attribute, value in (("readonly", "off"), ("isolation", "read committed")):
            db, _ = self.cohort(); setattr(db, attribute, value)
            self.reject(lambda: recovery.verify_restored_evidence(db, decrypt_bytes=self.key.decrypt))
            self.assertTrue(all(q.startswith("SHOW ") for q in db.queries), "Refuse before row read")

    def test_empty_missing_categories_wrong_expected_bytes_and_unknown_validation_owner_fail(self):
        self.reject(lambda: recovery.verify_restored_evidence(Database([]), decrypt_bytes=self.key.decrypt))
        for kind in ("bytes", "capture", "missing", "orphan", "no_derivative"):
            db, expected = self.cohort()
            if kind == "bytes": expected[self.original.id] = replace(expected[self.original.id], data=b"wrong")
            if kind == "capture": expected[self.original.id] = replace(expected[self.original.id], capture_json=None)
            if kind == "missing": expected.pop(self.original.id)
            if kind == "orphan": db.validations[self.validation.id] = replace(self.validation, evidence_id=str(uuid.uuid4()))
            if kind == "no_derivative": db.validations = {}
            self.reject(lambda: recovery.verify_restored_evidence(db, decrypt_bytes=self.key.decrypt, expected_cohort=expected))

    def test_row_and_total_caps_fail_instead_of_truncating_or_reading_oversize_cipher(self):
        db, expected = self.cohort()
        with patch.object(recovery, "MAX_TOTAL", 1):
            self.reject(lambda: recovery.verify_restored_evidence(db, decrypt_bytes=self.key.decrypt, expected_cohort=expected))
        rows = [original_fixture(self.key)[0] for _ in range(101)]
        self.reject(lambda: recovery.verify_restored_evidence(Database(rows), decrypt_bytes=self.key.decrypt))
        huge = replace(self.original, payload_ciphertext=b"x" * (recovery.MAX_CIPHER + 1))
        db = Database([huge])
        self.reject(lambda: recovery.verify_restored_evidence(db, decrypt_bytes=self.key.decrypt))
        self.assertTrue(not any(q.startswith("SELECT e.") for q in db.queries), "Length guard must precede ciphertext fetch")

    def test_public_receipt_keeps_only_closed_aggregate_and_never_unknown_private_values(self):
        value = {"schema": 1, "status": "UNAVAILABLE", "scope": "DISPOSABLE_TEST_COHORT", "application": "CLOSED",
                 "native_validation": "NOT_PROVEN_BY_THIS_TEST", "current_delivery": "NOT_EVALUATED",
                 "cleanup": "STOPPED_VERIFIED", "phases": ["FRESH_PRIVATE_TEST_ARCHIVE_VERIFIED"], "negative_cases": [],
                 "source_preserved": True, "retained_preserved": True, "private_files_preserved": True,
                 "archives_preserved": True, "fixture_key_preserved": True, "code": "PHOTO_RECOVERY_UNAVAILABLE"}
        self.assertTrue(public_recovery_receipt(value) == value, "Closed failure phase must remain observable")
        for key, private in (("extra", "PRIVATE_FIXTURE_CANARY"), ("code", "PRIVATE_FIXTURE_CANARY"),
                             ("phases", ["PRIVATE_FIXTURE_CANARY"]), ("source_preserved", 1)):
            changed = dict(value); changed[key] = private
            safe = public_recovery_receipt(changed)
            self.assertTrue(safe == {"schema": 1, "status": "UNAVAILABLE", "code": "INVALID_RECOVERY_RECEIPT"}, "Malformed receipt must not disclose")


# Import Django only inside the configured real test runner. Standalone pure
# unittest discovery has no settings/connection/DB side effect.
if os.environ.get("DJANGO_SETTINGS_MODULE") == "config.test_settings":
    from django.test import TransactionTestCase as _TransactionTestCase, override_settings

    @unittest.skipUnless(os.environ.get("KAPIT_PHOTO_RECOVERY_DRILL") == "1", "Root-only archive/restore opt-in absent")
    class EvidenceArchiveRecoveryTests(_TransactionTestCase):
        def test_committed_fixture_actual_archive_restore_and_negative_recovery(self):
            from django.contrib.auth import get_user_model
            from django.core.management import call_command
            from django.db import connection
            from django.utils import timezone as django_time
            from tests import browser_runner
            from tests.test_workflow import operation
            from apps.operations.evidence import accept_evidence
            from apps.operations import evidence_processing as processing
            from apps.operations.evidence_decoder import DecodedEvidence
            from apps.operations.models import PrivateEvidence, PrivateEvidenceValidation
            from apps.reports.services import accept_operation
            from infra.photo_recovery_drill import archive_restore
            from infra.evidence_tools import ToolManifest

            lease = browser_runner.ACTIVE_DATABASE_LEASE
            self.assertTrue(lease is not None, "Guarded source lease required")
            lease.assert_owned()
            browser_runner.require_target(connection.settings_dict, os.environ, running_test=True)
            self.assertTrue(not connection.in_atomic_block, "Committed source fixture required")
            key_bytes = Fernet.generate_key()
            key = Fernet(key_bytes)
            expected = {}
            with override_settings(KAPIT_SOURCE_KEY=key_bytes):
                call_command("seed_demo", verbosity=0)
                actor = get_user_model().objects.get(username="submitter")
                now = django_time.now()
                for index, metadata in enumerate((None, capture(now, False), capture(now))):
                    body = operation()
                    receipt, _ = accept_operation(actor, body, body)
                    data = png() if metadata is None else jpeg()
                    dto, _ = accept_evidence(actor, uuid.UUID(receipt["revision_id"]), uuid.uuid4(), data,
                        "image/png" if metadata is None else "image/jpeg", "legacy.png" if metadata is None else "capture.jpg", capture=metadata)
                    item = PrivateEvidence.objects.get(pk=dto["id"])
                    derivatives = ()
                    if index in (1, 2):
                        doc = fresh_manifest(django_time.now())
                        parsed = recovery.parse_manifest(recovery.canonical(doc), now=django_time.now())
                        manifest = ToolManifest(parsed.manifest_hash, parsed.signature_generation, parsed.expires_at,
                            parsed.policy_generation, doc["contract_sha256"], recovery.canonical(doc))
                        @contextmanager
                        def trusted_fixture():
                            yield manifest
                        scan = (dict(return_value="SCAN_CLEAN") if index == 2
                                else dict(side_effect=processing.tools.ToolUnavailable("ISOLATION_UNAVAILABLE")))
                        with patch.object(processing.tools, "current_tools", trusted_fixture), \
                             patch.object(processing.tools, "assert_current"), \
                             patch.object(processing.tools, "run_scan", **scan), \
                             patch.object(processing.tools, "decode", return_value=DecodedEvidence("image/png", 1, 1, 1, png())):
                            snapshot = processing.prepare_validation(actor, item.id, uuid.uuid4())
                            result = processing.run_validation(snapshot)
                            status = processing.commit_validation(actor, snapshot, result)
                        validation = PrivateEvidenceValidation.objects.get(validated_by=actor, operation_id=snapshot.operation_id)
                        self.assertTrue(status["validation_code"] == ("VALIDATION_COMPLETE" if index == 2 else "ISOLATION_UNAVAILABLE"), "Synthetic fixture outcome required")
                        if index == 2:
                            derivatives = ((str(validation.id), png()),)
                    expected[str(item.id)] = recovery.ExpectedEvidence(data, None if metadata is None else recovery.canonical(metadata), derivatives)
                lease.assert_owned()
                result = archive_restore(execute=True, reservation=secrets.token_hex(16), expected_cohort=expected, recovery_key=key_bytes)
            safe = public_recovery_receipt(result)
            print("PHOTO_RECOVERY_RECEIPT " + json.dumps(safe, sort_keys=True, separators=(",", ":")), flush=True)
            self.assertTrue(safe.get("status") == "ENCRYPTED_EVIDENCE_ARCHIVE_RECOVERY_VERIFIED", "Archive/restore recovery proof required")
            self.assertTrue(safe.get("cleanup") == "STOPPED_VERIFIED", "Verified owned cleanup required")
            self.assertTrue(safe.get("application") == "CLOSED", "No restored app may start")
            lease.assert_owned()
