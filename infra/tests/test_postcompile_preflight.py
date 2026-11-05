"""Pure contract/lifecycle tests; every host boundary is replaced."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import importlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from infra import evidence_postcompile_preflight as preflight
from infra import evidence_postcompile_diagnostic as old
from infra import evidence_native_refresh_runtime as refresh
from infra import evidence_native_runtime as runtime
from infra import evidence_tools, live_recovery_drill


def success():
    return {'schema': 1, 'scope': preflight.SCOPE, 'status': 'PREFLIGHT_COMPLETE',
        'completed': True, 'read_only': True, 'container_actions': False,
        'native_eligible': False, 'private_input_allowed': False, 'control_state_modified': False,
        'pins_closed': True, 'cli_cleanup_confirmed': True, 'source_sha256': 'a'*64,
        'frozen_controller_sha256': preflight.FROZEN_CONTROLLER_SHA256,
        'program_sha256': old.PROGRAM_SHA256, 'image_id': old.IMAGE,
        'signature_generation': old.GENERATION, 'completed_stages': list(preflight.SUCCESS_STAGES),
        'total_seconds': 1.25}


class SchemaTests(unittest.TestCase):
    def test_import_is_inert_at_all_host_boundaries(self):
        with patch.object(refresh, 'Receipt') as receipt, \
             patch.object(evidence_tools, 'Windows') as windows, \
             patch.object(old, 'Commands') as commands, \
             patch.object(old, 'legacy_lock') as lock, \
             patch.object(old, 'exclusive_lock') as dedicated, \
             patch.object(old, 'reserve') as reservation:
            importlib.reload(preflight)
        for boundary in (receipt, windows, commands, lock, dedicated, reservation):
            boundary.assert_not_called()

    def test_exact_success_provenance(self):
        preflight.validate_receipt(success(), 'a'*64)

    def test_missing_unknown_changed_and_bool_values_refuse(self):
        for key in success():
            with self.subTest(key=key):
                value = success(); del value[key]
                with self.assertRaises(old.DiagnosticUnavailable): preflight.validate_receipt(value, 'a'*64)
        for key, altered in [('schema', True), ('completed', 1), ('read_only', False),
            ('container_actions', True), ('pins_closed', False), ('cli_cleanup_confirmed', False),
            ('image_id', 'wrong'), ('source_sha256', 'b'*64), ('completed_stages', []),
            ('total_seconds', True), ('total_seconds', float('nan')), ('total_seconds', 600),
            ('total_seconds', -1), ('total_seconds', float('inf'))]:
            with self.subTest(key=key, altered=altered):
                value = success(); value[key] = altered
                with self.assertRaises(old.DiagnosticUnavailable): preflight.validate_receipt(value, 'a'*64)
        value = success(); value['measurement'] = {}
        with self.assertRaises(old.DiagnosticUnavailable): preflight.validate_receipt(value, 'a'*64)

    def test_frozen_source_byte_contract(self):
        self.assertEqual(hashlib.sha256((preflight.ROOT / preflight.FROZEN_CONTROLLER).read_bytes()).hexdigest(),
            preflight.FROZEN_CONTROLLER_SHA256)

    def test_both_refusal_pins_closed_schema(self):
        values = []
        for _, _, duration in preflight.REFUSALS:
            values.append(json.dumps({'schema': 1, 'scope': 'PUBLIC_POSTCOMPILE_CONTROLLER_DIAGNOSTIC_ONLY',
                'status': 'REFUSED', 'completed': False, 'control_state_modified': False,
                'native_eligible': False, 'pins_closed': True, 'private_input_allowed': False,
                'image_id': old.IMAGE, 'signature_generation': old.GENERATION,
                'failure_code': 'POSTCOMPILE_DIAGNOSTIC_REFUSED', 'total_seconds': duration}).encode())
        # Size/hash responsibilities belong to pin_bytes, size is also checked locally.
        values = [raw + b' '*(503-len(raw)) for raw in values]
        with patch.object(refresh, 'pin_bytes', side_effect=values) as pin:
            preflight.preserved_refusals(ExitStack(), object())
        self.assertEqual([call.kwargs['expected'] for call in pin.call_args_list],
            [row[1] for row in preflight.REFUSALS])
        duplicate = b'{"schema":1,"schema":1}'
        duplicate += b' '*(503-len(duplicate))
        for malformed in (b'{}', duplicate, b'[]'):
            with patch.object(refresh, 'pin_bytes', return_value=malformed):
                with self.assertRaises(Exception): preflight.preserved_refusals(ExitStack(), object())
        altered = json.loads(values[0]); altered['schema'] = True
        raw = json.dumps(altered).encode(); raw += b' '*(503-len(raw))
        with patch.object(refresh, 'pin_bytes', return_value=raw):
            with self.assertRaises(old.DiagnosticUnavailable): preflight.preserved_refusals(ExitStack(), object())
        altered = json.loads(values[0]); altered['unknown'] = 1
        raw = json.dumps(altered).encode(); raw += b' '*(503-len(raw))
        with patch.object(refresh, 'pin_bytes', return_value=raw):
            with self.assertRaises(old.DiagnosticUnavailable): preflight.preserved_refusals(ExitStack(), object())


class InputTests(unittest.TestCase):
    @contextmanager
    def fixture(self, mode=None):
        events = []; api = MagicMock()
        @contextmanager
        def pinned(path, **kwargs):
            events.append(('api', path, kwargs)); yield io.BytesIO()
        api.pin.side_effect = pinned
        private = MagicMock(); private.pin.side_effect = lambda *a, **k: ExitStack()
        @contextmanager
        def lock(*args):
            events.append('lock'); yield; events.append('unlock')
            if mode == 'close': raise OSError('hidden')
        with ExitStack() as stack:
            stack.enter_context(patch.object(preflight.os, 'name', 'nt'))
            stack.enter_context(patch.object(evidence_tools, 'Windows', return_value=api))
            stack.enter_context(patch.object(live_recovery_drill, 'PrivateDirectory', return_value=private))
            pin = stack.enter_context(patch.object(refresh, 'pin_bytes', return_value=b'program'))
            profile = stack.enter_context(patch.object(old, 'profile_source'))
            stack.enter_context(patch.object(preflight, 'preserved_refusals'))
            stack.enter_context(patch.object(refresh, 'tools', return_value=('docker', None, 'config', {})))
            stack.enter_context(patch.object(old, 'legacy_lock', side_effect=lock))
            original = stack.enter_context(patch.object(old, 'original_documents'))
            unknown = stack.enter_context(patch.object(old, 'unknown_diagnostics'))
            if mode == 'missing': pin.side_effect = FileNotFoundError()
            if mode == 'profile': profile.side_effect = old.DiagnosticUnavailable('PROFILE_BYTES_CHANGED')
            yield events, api, private, pin, profile, original, unknown

    def test_inherited_profile_private_directory_and_single_existing_lock_contracts(self):
        with self.fixture() as (events, api, private, pin, profile, original, unknown):
            marks = []
            with preflight.checked_inputs(marks.append) as ctx:
                self.assertIs(ctx.api, api); self.assertEqual(ctx.raw, b'program')
                self.assertIn('lock', events); self.assertNotIn('unlock', events)
                self.assertEqual(marks, list(preflight.SUCCESS_STAGES[:8]))
            self.assertEqual(events.count('lock'), 1); self.assertEqual(events.count('unlock'), 1)
            self.assertTrue(all(call.kwargs == {'directory': True} for call in api.pin.call_args_list))
            private.pin.assert_called_once_with(preflight.ROOT / old.STAGE, private=True, directory=True)
            profile.assert_called_once_with(preflight.ROOT, ctx.pins, api)
            original.assert_called_once(); unknown.assert_called_once()
            self.assertEqual(pin.call_args_list[0].kwargs['expected'], preflight.FROZEN_CONTROLLER_SHA256)
            api.protect.assert_not_called()

    def test_missing_source_or_changed_profile_never_yields_or_reaches_original(self):
        for mode in ('missing', 'profile'):
            with self.fixture(mode) as (_, _, _, _, _, original, unknown):
                with self.assertRaises(Exception):
                    with preflight.checked_inputs(lambda stage: None): self.fail('yielded')
                original.assert_not_called(); unknown.assert_not_called()

    def test_final_input_close_uncertainty_dominates(self):
        with self.fixture('close'):
            with self.assertRaises(old.DiagnosticUnavailable) as caught:
                with preflight.checked_inputs(lambda stage: None): pass
        self.assertEqual(caught.exception.code, 'INPUT_CLOSE_UNCONFIRMED')


class LiveTests(unittest.TestCase):
    def test_readonly_allowlist_blocks_all_mutations_and_unknown_queries_before_cli(self):
        call = MagicMock(return_value=(0, b'2\n', b'', 'EXIT')); call.count = 0; call.uncertain = False
        queries = preflight.ReadonlyQueries(call)
        for argv in (('create', old.IMAGE), ('container', 'start', old.OLD_CID),
            ('container', 'stop', old.OLD_CID), ('container', 'rm', old.OLD_CID),
            ('container', 'inspect', 'arbitrary'), ('info', '--format', '{{json .}}'),
            ('container', 'ls'), ('run', old.IMAGE)):
            with self.assertRaises(old.DiagnosticUnavailable): queries(*argv)
        with self.assertRaises(old.DiagnosticUnavailable): queries('info', '--format', '{{.ID}}', timeout=1)
        call.assert_not_called()
        queries('info', '--format', '{{.CgroupVersion}}', timeout=15)
        call.assert_called_once_with('info', '--format', '{{.CgroupVersion}}', timeout=15)
        self.assertEqual(queries.count, 0); self.assertFalse(queries.uncertain)

    def test_readonly_query_output_uncertainty_is_sticky(self):
        for value in ((0, b'2\n', b'warning', 'EXIT'), (0, b'2\n', b'', 'WALL_LIMIT'),
            (True, b'2\n', b'', 'EXIT'), (0, '2', b'', 'EXIT'), (0, b'x'*65537, b'', 'EXIT')):
            call = MagicMock(return_value=value); call.uncertain = False
            with self.assertRaises(old.DiagnosticUnavailable):
                preflight.ReadonlyQueries(call)('info', '--format', '{{.CgroupVersion}}')
            self.assertTrue(call.uncertain)

    def test_owner_guard_exact_query_and_uncertainty(self):
        call = MagicMock(return_value=(0, b'', b'', 'EXIT'))
        preflight.diagnostic_owner_absent(call)
        self.assertEqual(call.call_args.args, ('container', 'ls', '--all', '--no-trunc', '--filter',
            'label=org.kapit.owner=' + old.OWNER, '--format', '{{.ID}}'))
        for output in ((0, b'id\n', b'', 'EXIT'), (0, b'', b'', 'WALL_LIMIT'),
            (1, b'', b'', 'EXIT'), (True, b'', b'', 'EXIT'), (0, b'', b'error', 'EXIT')):
            call.return_value = output
            with self.assertRaises(old.DiagnosticUnavailable): preflight.diagnostic_owner_absent(call)

    def test_live_checks_repeat_full_chain_each_time_and_return_unsaved_observation(self):
        context = preflight.Context(object(), ExitStack(), SimpleNamespace(uncertain=False), b'program')
        observed = object(); stages = []
        with patch.object(refresh, 'verified_image', return_value={'image_id': old.IMAGE,
                'signature_generation': old.GENERATION}) as image, \
             patch.object(runtime, '_require_cgroup_v2') as cgroup, \
             patch.object(preflight.shutil, 'disk_usage', return_value=SimpleNamespace(free=old.FLOOR)), \
             patch.object(preflight, 'diagnostic_owner_absent') as owner, \
             patch.object(old, 'observe_original', return_value=observed) as original:
            for _ in range(2): self.assertIs(preflight.verify_live(context, stages.append), observed)
        self.assertEqual(image.call_count, 2); self.assertEqual(cgroup.call_count, 2)
        self.assertEqual(owner.call_count, 2); self.assertEqual(original.call_count, 2)
        self.assertEqual(stages, list(preflight.SUCCESS_STAGES[8:])*2)

    def test_failed_fresh_chain_never_queries_original(self):
        ctx = preflight.Context(object(), ExitStack(), object(), b'')
        with patch.object(refresh, 'verified_image', side_effect=RuntimeError()), \
             patch.object(old, 'observe_original') as original:
            with self.assertRaises(RuntimeError): preflight.verify_live(ctx, lambda _: None)
        original.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def exercise(self, mode='ok'):
        saved = []; receipt = MagicMock(); receipt.stream.closed = False
        receipt.save.side_effect = lambda value: saved.append(deepcopy(value))
        if mode == 'save': receipt.save.side_effect = OSError('hidden')
        if mode == 'receiptclose': receipt.close.side_effect = OSError('hidden')
        ctx = preflight.Context(object(), ExitStack(), SimpleNamespace(uncertain=False), b'')
        @contextmanager
        def inputs(mark):
            for stage in preflight.SUCCESS_STAGES[:8]: mark(stage)
            yield ctx
            if mode == 'inputclose': raise old.DiagnosticUnavailable('INPUT_CLOSE_UNCONFIRMED')
        def live(context, mark):
            for stage in preflight.SUCCESS_STAGES[8:]: mark(stage)
            if mode == 'live': raise RuntimeError('secret forbidden')
            if mode == 'uncertain': ctx.call.uncertain = True
        with patch.object(preflight.os, 'name', 'nt'), \
             patch.object(refresh, 'Receipt', return_value=receipt), \
             patch.object(preflight, 'checked_inputs', side_effect=inputs), \
             patch.object(preflight, 'verify_live', side_effect=live), \
             patch.object(preflight.time, 'monotonic', side_effect=[0, 601, 602] if mode == 'late' else [0, 1, 2]):
            try: return preflight.execute(), saved, None
            except BaseException as error: return None, saved, error

    def test_success_after_close_only_and_exact_schema(self):
        result, saved, error = self.exercise()
        self.assertIsNone(error)
        preflight.validate_receipt(result, result['source_sha256'])
        self.assertEqual(saved[-1], result)

    def test_query_close_uncertainty_deadline_never_reports_complete(self):
        for mode in ('inputclose', 'live', 'uncertain', 'late'):
            result, saved, error = self.exercise(mode)
            with self.subTest(mode=mode):
                self.assertIsNone(result); self.assertIsNotNone(error)
                self.assertFalse(saved[-1]['completed']); self.assertEqual(saved[-1]['status'], 'REFUSED')
                self.assertNotIn('secret forbidden', json.dumps(saved[-1]))
                if mode == 'inputclose': self.assertFalse(saved[-1]['pins_closed'])

    def test_final_receipt_write_or_handle_failure_refuses(self):
        for mode in ('save', 'receiptclose'):
            result, saved, error = self.exercise(mode)
            self.assertIsNone(result); self.assertEqual(error.code, 'RECEIPT_CLOSE_UNCONFIRMED')

    def test_fixed_receipt_reuse_refuses_before_inputs(self):
        with patch.object(preflight.os, 'name', 'nt'), \
             patch.object(refresh, 'Receipt', side_effect=FileExistsError), \
             patch.object(preflight, 'checked_inputs') as inputs:
            with self.assertRaises(FileExistsError): preflight.execute()
        inputs.assert_not_called()


if __name__ == '__main__': unittest.main()
