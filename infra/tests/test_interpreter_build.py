"""Authenticated source transformation tests; never run a native compiler."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from infra import evidence_interpreter_build as build
from infra import evidence_native_build as old
from infra.test_evidence_native_build import lock_document

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / 'infra/native'
ARCHIVE = ROOT / 'ai/state/private-scanner-source-review/clamav-1.4.6.source.tar.gz'
BEFORE = b'    engine->bytecode_mode = CL_BYTECODE_MODE_AUTO;\n    cli_detect_environment(&bcs->env);'
AFTER = (b'    if (engine->bytecode_mode != CL_BYTECODE_MODE_INTERPRETER)\n'
         b'        engine->bytecode_mode = CL_BYTECODE_MODE_AUTO;\n'
         b'    cli_detect_environment(&bcs->env);')
MEMBER = 'libclamav/bytecode.c'


class InterpreterBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patch = (NATIVE / 'clamav_interpreter.patch').read_bytes()
        cls.recipe = (NATIVE / 'Dockerfile.evidence-interpreter').read_bytes()
        cls.members = build._source_members(ARCHIVE.read_bytes())
        cls.outputs = build.apply_exact_patch(cls.members, cls.patch)

    def test_old_files_authenticate_and_new_module_has_only_declared_diff(self):
        raw = (ROOT / 'infra/evidence_native_build.py').read_bytes()
        self.assertEqual(old.sha256(raw), '2626b4e662e0f632ee52444e9bf68480b00d3a2d1ae9835294921798235b6702')
        original = ast.parse(raw)
        derived = ast.parse((ROOT / 'infra/evidence_interpreter_build.py').read_bytes())
        for tree in (original, derived):
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id in {'PATCH_SHA256', 'RECIPE_SHA256'} for x in node.targets):
                    node.value = ast.Constant('DECLARED_NEW_DIGEST')
                if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == 'MEMBERS' for x in node.targets):
                    pairs = [(k, v) for k, v in zip(node.value.keys, node.value.values) if k.value != MEMBER]
                    node.value.keys, node.value.values = map(list, zip(*pairs))
                if isinstance(node, ast.Constant) and node.value == '1.4.6-kapit-strict2':
                    node.value = '1.4.6-kapit-strict1'
                if isinstance(node, ast.Constant) and type(node.value) is str:
                    node.value = node.value.replace('plus just nine patched overlays', 'plus just seven patched overlays')
        self.assertEqual(ast.dump(original), ast.dump(derived))
        self.assertEqual(old.sha256((NATIVE / 'clamav_strict.patch').read_bytes()), '8e54280c6ad5c76c2748aae805a8cea85d69179ef9a57cbaf1af468a53db3eb4')
        self.assertEqual(old.sha256((NATIVE / 'Dockerfile.evidence').read_bytes()), 'a50b0a5b3bdddf9cf4a3e17b7e61172a996ec2973002937d2e55677c1a2a7239')

    def test_exact_ninth_original_and_overlay(self):
        self.assertEqual(len(self.members), 9)
        self.assertEqual(len(self.members[MEMBER]), 129291)
        self.assertEqual(build.sha256(self.members[MEMBER]), '84421778f125853bb235c7c98fbe4f5e36b1a259ed960a6797d940b1ab9ea48b')
        self.assertEqual(len(self.outputs[MEMBER]), 129358)
        self.assertEqual(build.sha256(self.outputs[MEMBER]), '70a4f0997e5077edd5da360fff3b02c465519e0970681495a241543846326ef6')

    def test_patch_prefix_and_all_eight_old_overlays_identical(self):
        prior_patch = (NATIVE / 'clamav_strict.patch').read_bytes()
        self.assertTrue(self.patch.startswith(prior_patch))
        prior_members = {name: self.members[name] for name in old.MEMBERS}
        prior_outputs = old.apply_exact_patch(prior_members, prior_patch)
        self.assertEqual(prior_outputs, {name: self.outputs[name] for name in old.MEMBERS})
        self.assertEqual(set(build.MEMBERS) - set(old.MEMBERS), {MEMBER})

    def test_all_bytes_outside_unique_reset_are_preserved(self):
        original = self.members[MEMBER]
        self.assertEqual(original.count(BEFORE), 1)
        self.assertEqual(self.outputs[MEMBER], original.replace(BEFORE, AFTER))
        prefix, suffix = original.split(BEFORE)
        self.assertTrue(self.outputs[MEMBER].startswith(prefix))
        self.assertTrue(self.outputs[MEMBER].endswith(suffix))
        self.assertIn(b'if (!bcs->count)', prefix)
        for branch in (b'dconfmask', b'cli_bytecode_prepare_interpreter', b'CL_BYTECODE_MODE_OFF', b'CL_EBYTECODE_TESTFAIL'):
            self.assertIn(branch, suffix)
        # This byte equality includes all startup/DCONF/selftest/error paths;
        # an independent native run must still establish compiled behavior.

    def test_recipe_only_adds_copy_and_exact_ninth_hash(self):
        raw = (NATIVE / 'Dockerfile.evidence').read_bytes()
        expected = raw.replace(b'patched/libclamav/others.c /build/source/libclamav/',
                               b'patched/libclamav/others.c patched/libclamav/bytecode.c /build/source/libclamav/')
        previous = b"'506f45a784aa8702e71b0c3d209143a6c3e78b5558943f4090ced04b7692f44b  /build/source/libclamav/others.c' | sha256sum -c -"
        addition = b"'506f45a784aa8702e71b0c3d209143a6c3e78b5558943f4090ced04b7692f44b  /build/source/libclamav/others.c' '70a4f0997e5077edd5da360fff3b02c465519e0970681495a241543846326ef6  /build/source/libclamav/bytecode.c' | sha256sum -c -"
        self.assertEqual(raw.count(previous), 1)
        self.assertEqual(self.recipe, expected.replace(previous, addition))
        self.assertEqual(build._fixed_recipe(self.recipe), self.recipe)
        self.assertIn(b'-DBYTECODE_RUNTIME=interpreter', self.recipe)
        self.assertEqual(build.MIN_BUILD_FREE_BYTES, old.MIN_BUILD_FREE_BYTES)
        self.assertEqual(build.MODULE_PINS, old.MODULE_PINS)
        self.assertEqual(build.WORKER_POLICY_SHA256, old.WORKER_POLICY_SHA256)

    def test_changed_recipe_or_old_recipe_refused(self):
        for value in ((NATIVE / 'Dockerfile.evidence').read_bytes(), self.recipe + b'\n', self.recipe.replace(b'--network=none', b'--network=host'), bytearray(self.recipe)):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(build.BuildUnavailable):
                    build._fixed_recipe(value)

    def test_patch_changed_trailing_unlisted_and_typed_bytes_refused(self):
        for value in (self.patch + b'\n', self.patch.replace(b'CL_BYTECODE_MODE_INTERPRETER', b'CL_BYTECODE_MODE_AUTO'), self.patch + b'--- a/libclamav/unlisted.c\n+++ b/libclamav/unlisted.c\n', bytearray(self.patch), None):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(build.BuildUnavailable):
                    build.apply_exact_patch(self.members, value)

    def test_missing_extra_changed_or_nonbytes_member_refused(self):
        altered = dict(self.members); del altered[MEMBER]
        extra = dict(self.members, unexpected=b'x')
        changed = dict(self.members); changed[MEMBER] += b'\n'
        wrong_type = dict(self.members); wrong_type[MEMBER] = bytearray(wrong_type[MEMBER])
        for value in (altered, extra, changed, wrong_type):
            with self.assertRaises(build.BuildUnavailable):
                build.apply_exact_patch(value, self.patch)

    def test_parser_zero_fuzz_wrong_position_context_and_count_refused(self):
        # Isolate parser defenses behind the already separate digest check.
        for value in (self.patch.replace(b'@@ -2663,7 +2663,8 @@', b'@@ -2662,7 +2662,8 @@'),
                      self.patch.replace(b'@@ -2663,7 +2663,8 @@', b'@@ -2663,8 +2663,8 @@'),
                      self.patch.replace(b'     cli_detect_environment(&bcs->env);', b'     cli_detect_environment(&wrong->env);'),
                      self.patch + b'garbage\n'):
            self.assertNotEqual(value, self.patch)
            with patch.object(build, 'PATCH_SHA256', build.sha256(value)):
                with self.assertRaises(build.BuildUnavailable):
                    build.apply_exact_patch(self.members, value)

    def test_duplicate_and_unlisted_member_parser_refused(self):
        tail = self.patch[len((NATIVE / 'clamav_strict.patch').read_bytes()):]
        for value in (self.patch + tail, self.patch.replace(b'--- a/libclamav/bytecode.c', b'--- a/libclamav/unlisted.c')):
            with patch.object(build, 'PATCH_SHA256', build.sha256(value)):
                with self.assertRaises(build.BuildUnavailable):
                    build.apply_exact_patch(self.members, value)

    def test_only_strict2_lock_is_accepted_and_native_permission_absent(self):
        doc = lock_document()
        doc.update(derived_version='1.4.6-kapit-strict2', patch_sha256=build.PATCH_SHA256)
        self.assertEqual(build.parse_lock(json.dumps(doc).encode())['derived_version'], '1.4.6-kapit-strict2')
        for version in ('1.4.6-kapit-strict1', '1.4.6-kapit-strict3', True, None):
            doc['derived_version'] = version
            with self.assertRaises(build.BuildUnavailable):
                build.parse_lock(json.dumps(doc).encode())
        self.assertFalse(build.SourceBuildInputs({}).runtime_eligible)

    def test_changed_truncated_or_wrong_type_source_refused(self):
        for raw in (b'', b'x' * 128, bytearray(b'x'), None):
            with self.assertRaises(build.BuildUnavailable):
                build._source_members(raw)

    def test_unchanged_disk_floor_and_bool_refusal(self):
        build.require_build_space(6 * 1024**3)
        for value in (True, 6 * 1024**3 - 1, -1, '6442450944'):
            with self.assertRaises(build.BuildUnavailable):
                build.require_build_space(value)


if __name__ == '__main__':
    unittest.main()
