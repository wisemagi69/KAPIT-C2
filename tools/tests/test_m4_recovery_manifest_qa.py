"""Independent pure synthetic recovery-metadata checks; no actual recovery."""
import copy
import dataclasses
import hashlib
import json
import unittest
from infra import m4_recovery_manifest as recovery


class RecoveryManifestIndependentQA(unittest.TestCase):
    def setUp(self):
        self.parts={name:("qa-"+name).encode() for name in recovery.COMPONENTS}
        common=dict(snapshot_id="a"*32,commit_id="b"*32,generation=27,schema=12)
        self.operations=[dict(operation_id="c"*32,payload_sha256="d"*64,state="PENDING",database_commit_sha256=""),
            dict(operation_id="e"*32,payload_sha256="f"*64,state="COMMITTED",database_commit_sha256=self.sha(self.parts["database"]))]
        self.manifest=dict(scope="SYNTHETIC_RECOVERY_MANIFEST_V1",version=1,**common,captured_utc="2026-10-24T12:00:01Z",
            components=[dict(id=name,path=recovery.PATHS[name],**common,size=len(raw),sha256=self.sha(raw),
            required_key_ids=["key-qa"] if name in recovery.ENCRYPTED else []) for name,raw in self.parts.items()],operations=self.operations)
        self.authority=dict(scope="SYNTHETIC_CURRENT_RECOVERY_MODEL_V1",version=1,**common,issued_utc="2026-10-24T12:00:00Z",
            expires_utc="2026-10-24T12:01:00Z",component_sha256={n:self.sha(v) for n,v in self.parts.items()},
            operation_sha256={},active_key_ids=["key-qa"],revoked_key_ids=["key-old"])
        self.bind()

    @staticmethod
    def sha(raw): return hashlib.sha256(raw).hexdigest()

    def bind(self):
        self.authority["operation_sha256"]={op["operation_id"]:self.sha(recovery.canonical(op)) for op in self.operations}

    def validate(self,raw=None,authority=None,**changes):
        args=dict(components=self.parts,available_key_ids=("key-qa",),now_utc="2026-10-24T12:00:02Z");args.update(changes)
        return recovery.validate_synthetic_manifest(recovery.canonical(self.manifest) if raw is None else raw,
            recovery.canonical(self.authority) if authority is None else authority,**args)

    def test_positive_count_only_no_authority_and_frozen(self):
        before=copy.deepcopy((self.manifest,self.authority,self.parts))
        result=self.validate()
        self.assertEqual((result.component_count,result.committed_operations,result.pending_operations_retained),(9,1,1))
        self.assertEqual(result.status,"SYNTHETIC_PREPARATION_ONLY")
        self.assertFalse(result.recovery_authority or result.decryption_verified or result.semantic_coherence_verified)
        self.assertEqual(before,(self.manifest,self.authority,self.parts))
        self.assertNotIn("key-qa",repr(result))
        with self.assertRaises(dataclasses.FrozenInstanceError): result.recovery_authority=True

    def test_every_component_corrupt_even_if_manifest_updated(self):
        for name in recovery.COMPONENTS:
            with self.subTest(name=name):
                parts=dict(self.parts);parts[name]+=b"different"
                manifest=copy.deepcopy(self.manifest);row=next(x for x in manifest["components"] if x["id"]==name)
                row.update(size=len(parts[name]),sha256=self.sha(parts[name]))
                with self.assertRaises(recovery.RecoveryRefused): self.validate(raw=recovery.canonical(manifest),components=parts)

    def test_missing_extra_and_byteslike_components(self):
        for mode in ("missing","extra","mutable","empty","big"):
            parts=dict(self.parts)
            if mode=="missing":parts.pop("photos")
            elif mode=="extra":parts["other"]=b"x"
            elif mode=="mutable":parts["photos"]=bytearray(parts["photos"])
            elif mode=="empty":parts["photos"]=b""
            else:parts["photos"]=b"x"*(recovery.MAX_COMPONENT+1)
            with self.assertRaises(recovery.RecoveryRefused):self.validate(components=parts)

    def test_component_exact_size_boundary(self):
        raw=b"x"*recovery.MAX_COMPONENT;self.parts["photos"]=raw
        row=next(x for x in self.manifest["components"] if x["id"]=="photos");row.update(size=len(raw),sha256=self.sha(raw))
        self.authority["component_sha256"]["photos"]=self.sha(raw)
        self.assertEqual(self.validate().component_count,9)

    def test_manifest_authority_identity_mismatch(self):
        for key in ("snapshot_id","commit_id","generation","schema"):
            current=self.authority[key];self.authority[key]="1"*32 if isinstance(current,str) else current+1
            with self.assertRaises(recovery.RecoveryRefused):self.validate()
            self.authority[key]=current

    def test_each_row_identity_strict_types(self):
        row=self.manifest["components"][-1]
        for key,value in (("generation",True),("schema",12.0),("snapshot_id","0"*32),("commit_id","f"*32)):
            old=row[key];row[key]=value
            with self.assertRaises(recovery.RecoveryRefused):self.validate()
            row[key]=old

    def test_exact_paths_order_and_duplicate_rows(self):
        for mode in ("order","duplicate","traversal","drive","stream"):
            m=copy.deepcopy(self.manifest)
            if mode=="order":m["components"].reverse()
            elif mode=="duplicate":m["components"][-1]=m["components"][0]
            else:m["components"][0]["path"]={"traversal":"../db.bin","drive":"C:/db.bin","stream":"components/database.bin:secret"}[mode]
            with self.assertRaises(recovery.RecoveryRefused):self.validate(raw=recovery.canonical(m))

    def test_revocation_current_model_binding_cannot_be_replaced(self):
        for name in ("revocations","policy","sources","key_index"):
            row=next(x for x in self.manifest["components"] if x["id"]==name);old=row["sha256"];row["sha256"]="1"*64
            with self.assertRaises(recovery.RecoveryRefused):self.validate()
            row["sha256"]=old

    def test_missing_revoked_unknown_duplicate_available_keys(self):
        for ids in ((),("key-old",),("key-other",),("key-qa","key-qa"),["key-qa"],("BAD",)):
            with self.assertRaises(recovery.RecoveryRefused):self.validate(available_key_ids=ids)
        self.authority["revoked_key_ids"].append("key-qa")
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_encryption_key_reference_bounds(self):
        encrypted=self.manifest["components"][0];unencrypted=self.manifest["components"][-1]
        encrypted["required_key_ids"]=[]
        with self.assertRaises(recovery.RecoveryRefused):self.validate()
        encrypted["required_key_ids"]=["key-qa"];unencrypted["required_key_ids"]=["key-qa"]
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_fake_clock_window_edges_and_bad_dates(self):
        for now in ("2026-10-24T12:00:00Z","2026-10-24T12:01:00Z","2026-02-30T12:00:02Z",True,"2026-10-24T12:00:02+00:00"):
            with self.assertRaises(recovery.RecoveryRefused):self.validate(now_utc=now)
        self.assertEqual(self.validate(now_utc="2026-10-24T12:00:01Z").component_count,9)

    def test_no_indefinite_current_model_window(self):
        self.authority["expires_utc"]="2026-10-24T14:00:00Z"
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_partial_commit_rejected_even_if_model_agrees(self):
        self.operations[1]["state"]="PARTIAL";self.bind()
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_pending_payload_hash_cannot_change_behind_current_model(self):
        self.operations[0]["payload_sha256"]="1"*64
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_pending_operation_cannot_disappear_or_promote(self):
        old=self.operations.pop(0)
        with self.assertRaises(recovery.RecoveryRefused):self.validate()
        self.operations.insert(0,old);old["state"]="COMMITTED";old["database_commit_sha256"]=self.authority["component_sha256"]["database"]
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_committed_and_pending_commit_markers(self):
        for index,value in ((0,"1"*64),(1,"")):
            old=self.operations[index]["database_commit_sha256"];self.operations[index]["database_commit_sha256"]=value;self.bind()
            with self.assertRaises(recovery.RecoveryRefused):self.validate()
            self.operations[index]["database_commit_sha256"]=old;self.bind()

    def test_duplicate_operation_and_extra_binding(self):
        self.operations.append(dict(self.operations[0]));self.bind()
        with self.assertRaises(recovery.RecoveryRefused):self.validate()
        self.operations.pop();self.bind();self.authority["operation_sha256"]["2"*32]="3"*64
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_operation_maximum_and_overflow(self):
        self.operations[:]=[dict(operation_id=f"{i+1:032x}",payload_sha256="d"*64,state="PENDING",database_commit_sha256="") for i in range(recovery.MAX_OPERATIONS)]
        self.bind();self.assertEqual(self.validate().pending_operations_retained,128)
        self.operations.append(dict(operation_id="f"*32,payload_sha256="d"*64,state="PENDING",database_commit_sha256=""));self.bind()
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_raw_size_canonical_duplicate_and_unknown_fields(self):
        raw=recovery.canonical(self.manifest)
        for changed in (b" "*(recovery.MAX_METADATA+1),b"",b" "+raw,raw.replace(b'"version":1',b'"version":1,"version":1')):
            with self.assertRaises(recovery.RecoveryRefused):self.validate(raw=changed)
        self.manifest["extra"]="synthetic"
        with self.assertRaises(recovery.RecoveryRefused):self.validate()

    def test_refusal_has_no_input_bearing_context_or_cause(self):
        with self.assertRaises(recovery.RecoveryRefused) as caught:self.validate(raw=b'{"synthetic-canary":')
        self.assertEqual(str(caught.exception),"SYNTHETIC_RECOVERY_PREPARATION_REFUSED")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_production_refuses_before_input_access(self):
        class Poison:
            def __getattribute__(self,name):raise AssertionError(name)
        with self.assertRaises(recovery.RecoveryRefused):recovery.production_restore(Poison())
