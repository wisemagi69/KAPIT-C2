"""Pure synthetic buffers/fake clocks. No keys, files, databases or restore."""
import dataclasses
import hashlib
import json
import unittest
from infra import m4_recovery_manifest as r

NOW = "2026-10-24T00:00:02Z"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.buffers = {name: ("synthetic-" + name).encode("ascii") for name in r.COMPONENTS}
        self.common = dict(snapshot_id="1" * 32, commit_id="2" * 32, generation=3, schema=4)
        self.rows = [dict(id=name, path=r.PATHS[name], **self.common, size=len(self.buffers[name]),
                         sha256=r._digest(self.buffers[name]),
                         required_key_ids=["key-a"] if name in r.ENCRYPTED else [])
                     for name in r.COMPONENTS]
        self.operations = [dict(operation_id="3" * 32, payload_sha256="a" * 64,
                                state="COMMITTED", database_commit_sha256=r._digest(self.buffers["database"])),
                           dict(operation_id="4" * 32, payload_sha256="b" * 64,
                                state="PENDING", database_commit_sha256="")]
        self.manifest = dict(scope="SYNTHETIC_RECOVERY_MANIFEST_V1", version=1, **self.common,
                             captured_utc="2026-10-24T00:00:01Z", components=self.rows, operations=self.operations)
        self.authority = dict(scope="SYNTHETIC_CURRENT_RECOVERY_MODEL_V1", version=1, **self.common,
                              issued_utc="2026-10-24T00:00:00Z", expires_utc="2026-10-24T00:05:00Z",
                              component_sha256={name:r._digest(raw) for name,raw in self.buffers.items()},
                              operation_sha256={}, active_key_ids=["key-a"], revoked_key_ids=["key-old"])
        self.bind_operations()

    def bind_operations(self):
        self.authority["operation_sha256"] = {op["operation_id"]:r._digest(r.canonical(op)) for op in self.operations}

    def prepare(self, **changes):
        kw = dict(components=self.buffers, available_key_ids=("key-a",), now_utc=NOW)
        kw.update(changes)
        return r.validate_synthetic_manifest(r.canonical(self.manifest), r.canonical(self.authority), **kw)

    def test_complete_synthetic_preparation_is_not_recovery_authority(self):
        result = self.prepare()
        self.assertEqual(result.status, "SYNTHETIC_PREPARATION_ONLY")
        self.assertEqual(result.component_count, 9)
        self.assertEqual((result.committed_operations,result.pending_operations_retained), (1,1))
        self.assertFalse(result.recovery_authority or result.decryption_verified or result.semantic_coherence_verified)
        self.assertNotIn("key-a", repr(result))
        with self.assertRaises(dataclasses.FrozenInstanceError): result.status = "RESTORED"

    def test_corrupt_each_component_refuses(self):
        for name in r.COMPONENTS:
            with self.subTest(name=name):
                changed = dict(self.buffers); changed[name] += b"corrupt"
                with self.assertRaises(r.RecoveryRefused): self.prepare(components=changed)

    def test_missing_or_unknown_component_refuses(self):
        for mode in ("missing", "unknown"):
            changed = dict(self.buffers)
            if mode == "missing": del changed["coordinates"]
            else: changed["other"] = b"fixture"
            with self.assertRaises(r.RecoveryRefused): self.prepare(components=changed)

    def test_duplicate_order_and_path_refuse(self):
        for field,value in (("id", "database"), ("path", "../private.bin"), ("path", "C:/private.bin"),
                            ("path", "components/photos.bin:stream")):
            old = self.rows[2][field]; self.rows[2][field] = value
            with self.assertRaises(r.RecoveryRefused): self.prepare()
            self.rows[2][field] = old
        self.rows.reverse()
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_cross_component_snapshot_commit_generation_schema_refuse(self):
        for field in self.common:
            old = self.rows[3][field]
            self.rows[3][field] = "9" * 32 if type(old) is str else old+1
            with self.assertRaises(r.RecoveryRefused): self.prepare()
            self.rows[3][field] = old

    def test_current_authority_snapshot_mismatch_refuses(self):
        for field in self.common:
            old = self.authority[field]
            self.authority[field] = "9"*32 if type(old) is str else old+1
            with self.assertRaises(r.RecoveryRefused): self.prepare()
            self.authority[field] = old

    def test_stale_revocation_policy_source_or_keyindex_refuses(self):
        for name in ("revocations", "policy", "sources", "key_index"):
            original = self.authority["component_sha256"][name]
            self.authority["component_sha256"][name] = "f"*64
            with self.assertRaises(r.RecoveryRefused): self.prepare()
            self.authority["component_sha256"][name] = original

    def test_missing_wrong_revoked_duplicate_key_ids_refuse(self):
        for keys in ((), ("key-wrong",), ("key-old",), ("key-a", "key-a"), ["key-a"], (b"secret",)):
            with self.assertRaises(r.RecoveryRefused): self.prepare(available_key_ids=keys)
        self.authority["revoked_key_ids"].append("key-a")
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_encrypted_components_need_key_metadata_others_must_not(self):
        self.rows[0]["required_key_ids"] = []
        with self.assertRaises(r.RecoveryRefused): self.prepare()
        self.rows[0]["required_key_ids"] = ["key-a"]
        self.rows[4]["required_key_ids"] = ["key-a"]
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_fake_clock_future_expired_and_invalid_refuse(self):
        for clock in ("2026-10-23T23:59:59Z", "2026-10-24T00:05:00Z", "2026-02-30T00:00:00Z",
                      "2026-10-24T00:00:02+00:00", None):
            with self.assertRaises(r.RecoveryRefused): self.prepare(now_utc=clock)

    def test_authority_lifetime_and_capture_outside_window_refuse(self):
        self.authority["expires_utc"] = "2026-10-24T02:00:00Z"
        with self.assertRaises(r.RecoveryRefused): self.prepare()
        self.authority["expires_utc"] = "2026-10-24T00:05:00Z"
        self.manifest["captured_utc"] = "2026-10-23T23:59:59Z"
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_partial_commit_refuses_even_with_matching_model(self):
        self.operations[0]["state"] = "PARTIAL"
        self.bind_operations()
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_pending_never_promoted_by_preparation(self):
        result = self.prepare()
        self.assertEqual(self.operations[1]["state"], "PENDING")
        self.assertEqual(result.pending_operations_retained, 1)

    def test_duplicate_conflicting_immutable_payload_refuses(self):
        other = dict(self.operations[0]); other["payload_sha256"] = "c"*64
        self.operations.append(other)
        self.bind_operations()
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_stable_operation_payload_and_missing_pending_binding_refuse(self):
        self.operations[0]["payload_sha256"] = "c"*64
        with self.assertRaises(r.RecoveryRefused): self.prepare()
        self.operations[0]["payload_sha256"] = "a"*64
        self.operations.pop()
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_committed_database_reference_and_pending_reference_refuse(self):
        for index,value in ((0,"f"*64), (1,"f"*64)):
            old = self.operations[index]["database_commit_sha256"]
            self.operations[index]["database_commit_sha256"] = value
            self.bind_operations()
            with self.assertRaises(r.RecoveryRefused): self.prepare()
            self.operations[index]["database_commit_sha256"] = old

    def test_component_and_metadata_limits(self):
        changed=dict(self.buffers); changed["database"] = b"x"*(r.MAX_COMPONENT+1)
        with self.assertRaises(r.RecoveryRefused): self.prepare(components=changed)
        raw = b" " * (r.MAX_METADATA+1)
        with self.assertRaises(r.RecoveryRefused):
            r.validate_synthetic_manifest(raw,r.canonical(self.authority),components=self.buffers,
                                          available_key_ids=("key-a",),now_utc=NOW)

    def test_exact_component_and_operation_bounds_positive_then_overflow(self):
        self.buffers["database"] = b"x" * r.MAX_COMPONENT
        digest = r._digest(self.buffers["database"])
        self.rows[0].update(size=r.MAX_COMPONENT, sha256=digest)
        self.authority["component_sha256"]["database"] = digest
        self.operations[:] = [dict(operation_id=f"{n+1:032x}", payload_sha256="a"*64,
                                   state="PENDING",database_commit_sha256="")
                              for n in range(r.MAX_OPERATIONS)]
        self.bind_operations()
        result=self.prepare()
        self.assertEqual(result.pending_operations_retained,r.MAX_OPERATIONS)
        self.operations.append(dict(self.operations[-1],operation_id=f"{r.MAX_OPERATIONS+1:032x}"))
        self.bind_operations()
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_noncanonical_json_and_nonbytes_components_refuse(self):
        raw = json.dumps(self.manifest).encode("ascii")
        with self.assertRaises(r.RecoveryRefused):
            r.validate_synthetic_manifest(raw,r.canonical(self.authority),components=self.buffers,
                                          available_key_ids=("key-a",),now_utc=NOW)
        for payload in (bytearray(b"x"), "fixture", b""):
            changed=dict(self.buffers); changed["photos"] = payload
            with self.assertRaises(r.RecoveryRefused): self.prepare(components=changed)

    def test_duplicate_json_keys_unknown_fields_and_bool_schema_refuse(self):
        raw = r.canonical(self.manifest)
        duplicated = raw.replace(b'"version":1',b'"version":1,"version":1')
        with self.assertRaises(r.RecoveryRefused):
            r.validate_synthetic_manifest(duplicated,r.canonical(self.authority),components=self.buffers,
                                          available_key_ids=("key-a",),now_utc=NOW)
        self.manifest["schema"] = True
        with self.assertRaises(r.RecoveryRefused): self.prepare()
        self.manifest["schema"] = 4
        self.manifest["secret_key"] = "never accepted"
        with self.assertRaises(r.RecoveryRefused): self.prepare()

    def test_fixed_error_and_production_never_touches_inputs(self):
        class Trap:
            def __getattribute__(self,name): raise AssertionError("touched")
        with self.assertRaisesRegex(r.RecoveryRefused,"^SYNTHETIC_RECOVERY_PREPARATION_REFUSED$"):
            r.production_restore(Trap())
        with self.assertRaises(r.RecoveryRefused) as failure:
            self.prepare(available_key_ids=("key-privateid",))
        self.assertNotIn("privateid",str(failure.exception))

    def test_malformed_metadata_has_no_retained_decoder_exception_context(self):
        for raw in (b'{"private-canary":', b'\xffprivate-canary', b'{"private-canary":NaN}'):
            with self.subTest(raw_type="malformed synthetic metadata"):
                try:
                    r.validate_synthetic_manifest(raw,r.canonical(self.authority),
                        components=self.buffers,available_key_ids=("key-a",),now_utc=NOW)
                except r.RecoveryRefused as failure:
                    self.assertIsNone(failure.__context__)
                    self.assertIsNone(failure.__cause__)
                    self.assertNotIn("canary",repr(failure))
                else:
                    self.fail("malformed input accepted")


if __name__ == "__main__":
    unittest.main()
