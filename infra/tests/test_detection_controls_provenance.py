"""Copied public journal fixtures and mocked protected APIs; no private reads."""
import builtins
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
import hashlib
import importlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from infra import evidence_detection_controls_provenance as p
from infra import evidence_interpreter_runtime as current
from infra import evidence_rmdir_diagnostic as diagnostic
from infra import evidence_strict_category_v2_controller as controller
from infra import evidence_strict_category_v2_provenance as inherited


def fixture():
    receipt = json.loads(Path(p._RECEIPT).read_text())
    rows = receipt['preserved_originals'] + [receipt['new_original']]
    docs = {row['directory']+'/'+name: json.dumps(info['document'], sort_keys=True,
        separators=(',', ':')).encode() for row in rows for name, info in row['files'].items()}
    return receipt, rows, docs


class ProtectedReplay:
    def __init__(self):
        self.value, self.rows, self.docs = fixture()
        self.root = Path.cwd().resolve()
        self.directories = [self.root / row['directory'] for row in self.rows]
        self.reads, self.pins = [], []
        self.overrides = {}
        self.entered = self.exited = 0

    def read(self, root, pins, api, path, **kwargs):
        self.reads.append(path)
        self.pins.append((path, kwargs))
        if path in self.overrides:
            raw = self.overrides[path]
            if isinstance(raw, BaseException):
                raise raw
        elif 'native-run-' in path:
            # Never fall back to the actual private runtime directory.
            if path not in self.docs:
                raise FileNotFoundError('PRIVATE_CANARY')
            raw = self.docs[path]
        else:
            raw = Path(path).read_bytes()
        if 'expected' in kwargs:
            if hashlib.sha256(raw).hexdigest() != kwargs['expected']:
                raise ValueError('PRIVATE_PIN_CANARY')
        if len(raw) > kwargs.get('maximum', 262144):
            raise ValueError('PRIVATE_SIZE_CANARY')
        return raw

    @contextmanager
    def pin(self, path, **kwargs):
        if kwargs != {'private': True, 'directory': True}:
            raise AssertionError('Directory not protected')
        self.entered += 1
        try:
            yield
        finally:
            self.exited += 1

    def replay(self):
        prepared = json.loads(Path(diagnostic.receipt_path('prepare')).read_text())['preparation']
        with patch.object(current, 'pin_bytes', side_effect=self.read), \
                patch.object(Path, 'glob', return_value=iter(self.directories)), \
                patch('infra.live_recovery_drill.PrivateDirectory') as private:
            # Each inherited traversal must receive a fresh generator.
            with patch.object(Path, 'glob', side_effect=lambda *a: iter(self.directories)):
                private.return_value.pin = self.pin
                with ExitStack() as pins:
                    result = p.preserved_originals(self.root, pins, Mock(), prepared)
                    if self.entered != 0 and self.exited != 0:
                        raise AssertionError('Protected context released early')
                return result


class DetectionProvenanceTests(unittest.TestCase):
    def assert_private_refusal(self, action):
        try:
            action()
        except p.ProvenanceUnavailable as error:
            self.assertEqual(error.args, ('PUBLIC_DETECTION_CONTROL_PROVENANCE_UNAVAILABLE',))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            return
        self.fail('Expected fixed refusal')

    def test_fixed_closed_fresh_immutable_binding(self):
        first, second = p.binding(), p.binding()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(tuple(asdict(first)), p._FIELDS)
        self.assertFalse(hasattr(first, '__dict__'))
        with self.assertRaises(FrozenInstanceError):
            first.image_id = 'PRIVATE_CANARY'
        projection = p.binding_fields(first)
        projection['contract'] = 'PRIVATE_CANARY'
        self.assertEqual(p.binding_fields(first)['contract'], p.CONTRACT)

    def test_binding_each_field_and_wrong_shapes_refuse(self):
        for field in p._FIELDS:
            value = p.binding()
            object.__setattr__(value, field, 'PRIVATE_CANARY')
            self.assert_private_refusal(lambda: p.binding_fields(value))
        for value in (None, {}, asdict(p.binding()), object.__new__(p._Binding)):
            self.assert_private_refusal(lambda: p.binding_fields(value))

    def test_contract_matches_versioned_fixed_input_description(self):
        expected = hashlib.sha256(json.dumps(p._CONTRACT_DOCUMENT, separators=(',', ':')).encode('ascii')).hexdigest()
        self.assertEqual(p.CONTRACT, expected)
        self.assertEqual(len(p.PINNED_INPUTS), 54)
        snapshot = json.loads(Path('ai/state/detection-controls-provenance-snapshot.json').read_text())['files']
        self.assertEqual(dict(p.PINNED_INPUTS), snapshot)

    def test_all54_pins_precede_first_inherited_import(self):
        events = []
        original_import = builtins.__import__

        def import_hook(name, *args, **kwargs):
            if name == 'infra' and args and 'evidence_strict_category_v2_controller' in (args[2] or ()):
                events.append('CONTROLLER_IMPORT')
            return original_import(name, *args, **kwargs)

        def read(*args, **kwargs):
            events.append(args[3])
            return b''
        with patch.object(current, 'pin_bytes', side_effect=read), \
                patch.object(controller, '_pin_sources') as transitive, \
                patch('builtins.__import__', side_effect=import_hook):
            self.assertEqual(p.pin_sources(Path('.'), ExitStack(), Mock()), p.binding())
        self.assertEqual(events[:54], [path for path, _ in p.PINNED_INPUTS])
        self.assertEqual(events[54], 'CONTROLLER_IMPORT')
        transitive.assert_called_once()

    def test_every_changed_fixed_pin_stops_before_inherited_validator(self):
        for denied, _ in p.PINNED_INPUTS:
            with self.subTest(path=denied):
                def read(root, pins, api, path, **kwargs):
                    if path == denied:
                        raise RuntimeError('PRIVATE_CHANGED_PIN')
                    return b''
                with patch.object(current, 'pin_bytes', side_effect=read), \
                        patch.object(controller, '_pin_sources') as transitive:
                    self.assert_private_refusal(lambda: p.pin_sources(Path('.'), ExitStack(), Mock()))
                transitive.assert_not_called()

    def test_all28_originals112_actual_canonical_documents_replayed(self):
        replay = ProtectedReplay()
        rows = replay.replay()
        reads = {path for path in replay.reads if 'native-run-' in path}
        self.assertEqual(len(rows), 28)
        self.assertEqual(len({row['token'] for row in rows}), 28)
        self.assertEqual(len({row['original_id'] for row in rows}), 28)
        self.assertEqual(sum(len(row['files']) for row in rows), 112)
        self.assertEqual(len(reads), 112)
        self.assertEqual((replay.entered, replay.exited), (replay.entered, replay.entered))
        self.assertGreater(replay.entered, 28)

    def test_each_of112_journal_corruptions_refuses(self):
        # Positive replay above traverses the full provenance chain. Fault each
        # record through its unchanged canonical-journal helper without repeating
        # every unrelated source pin and ancestor receipt for all112 scenarios.
        _, rows, _ = fixture()
        for row in rows:
            for name in row['files']:
                with self.subTest(token=row['token'], name=name):
                    replay = ProtectedReplay()
                    replay.docs[row['directory']+'/'+name] += b' '
                    with patch.object(current, 'pin_bytes', side_effect=replay.read), \
                            patch('infra.live_recovery_drill.PrivateDirectory') as private:
                        private.return_value.pin = replay.pin
                        with ExitStack() as pins, self.assertRaises(diagnostic.DiagnosticUnavailable):
                            diagnostic.journal_documents(replay.root, pins, Mock(), row['token'],
                                row['files']['reservation.json']['document'], row['original_id'], row['files'])

    def test_each_v2_journal_missing_refuses(self):
        value, _, _ = fixture()
        for name in ('reservation.json', 'create-attempt.json', 'ownership.json', 'result.json'):
            replay = ProtectedReplay()
            del replay.docs[value['new_original']['directory']+'/'+name]
            self.assert_private_refusal(replay.replay)

    def test_v2_missing_original_and_duplicate_rows_refuse(self):
        value, rows, _ = fixture()
        for mutation in (lambda x: x.pop(), lambda x: x.append(deepcopy(x[-1])),
                         lambda x: x.__setitem__(0, deepcopy(x[-1])),
                         lambda x: x[0].update(original_id=x[1]['original_id'])):
            changed = deepcopy(rows)
            mutation(changed)
            self.assert_private_refusal(lambda: self.row_check(changed))
        replay = ProtectedReplay()
        replay.directories = replay.directories[:-1]
        self.assert_private_refusal(replay.replay)

    @staticmethod
    def row_check(rows):
        failed = False
        try:
            p._row_set(rows)
        except BaseException:
            failed = True
        if failed:
            raise p.ProvenanceUnavailable()

    def test_consumed_exact_case_finalizers_and_false_flags(self):
        value, _, _ = fixture()
        expected = controller.binding(dict(p.PINNED_INPUTS)[p._CONTROLLER])
        p._validate_consumed(value, controller, expected)
        self.assertEqual(value['status'], 'MEASURED')
        self.assertEqual(value['observation']['details']['failed_case_ids'], ['eicar_png'])
        changes = (
            lambda d: d.update(schema=True), lambda d: d.update(status='REFUSED'),
            lambda d: d.update(completed=False), lambda d: d.update(native_eligible=True),
            lambda d: d.update(private_input_allowed=True), lambda d: d.update(control_state_modified=True),
            lambda d: d['finalizers'].update(cli='UNCONFIRMED'),
            lambda d: d['observation']['details'].update(case_count=True),
            lambda d: d['observation']['details'].update(case_count=13),
            lambda d: d['observation']['details'].update(failed_case_ids=['png_positive']),
            lambda d: d['observation']['details']['failed_cases'][0].update(strict='NOT_CLEAN'),
            lambda d: d['observation']['details']['failed_cases'][0].update(upstream='ERROR'),
            lambda d: d['observation']['details']['failed_cases'][0].update(normalization_observed=0),
            lambda d: d.update(extra='PRIVATE_CANARY'))
        for mutation in changes:
            changed = deepcopy(value)
            mutation(changed)
            with self.subTest(change=changes.index(mutation)), self.assertRaises(Exception):
                p._validate_consumed(changed, controller, expected)

    def test_changed_receipt_pin_refuses_before_replay(self):
        for path in (p._RECEIPT, p._PREFLIGHT, p._V1):
            replay = ProtectedReplay()
            replay.overrides[path] = Path(path).read_bytes() + b' '
            with patch.object(controller, '_postflight_originals') as postflight:
                self.assert_private_refusal(replay.replay)
            postflight.assert_not_called()

    def test_preserved_v1_refusal_and_old_strict_negative_guard(self):
        replay = ProtectedReplay()
        old = Path('ai/state/private-scanner-rmdir-proof-strict.json').read_bytes()
        replay.replay()
        self.assertEqual(old, Path('ai/state/private-scanner-rmdir-proof-strict.json').read_bytes())
        value = json.loads(Path(p._V1).read_text())
        self.assertEqual(inherited.validate_v1_preflight(value)['status'], 'REFUSED')
        self.assertEqual(value['finalizers']['phase_pins'], 'NOT_REACHED')
        self.assertFalse(json.loads(old)['pins_closed'])

    def test_unknown_foreign_owner_and_image_refuse_unconditionally(self):
        for foreign in ('owner', 'image', 'both'):
            replay = ProtectedReplay()
            document = deepcopy(replay.rows[-1]['files']['reservation.json']['document'])
            token = 'f'*32
            document['token'] = token
            document['expected_labels']['org.kapit.reservation'] = token
            if foreign in ('owner', 'both'):
                document['expected_labels']['org.kapit.owner'] = 'foreign'
                document['expected_labels']['org.kapit.purpose'] = 'foreign'
                document['purpose'] = 'foreign'
            if foreign in ('image', 'both'):
                document['image_id'] = 'sha256:'+'f'*64
            directory = self.root_directory(replay, token)
            replay.directories.append(directory)
            replay.docs[directory.relative_to(replay.root).as_posix()+'/reservation.json'] = \
                json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
            self.assert_private_refusal(replay.replay)

    @staticmethod
    def root_directory(replay, token):
        return replay.root / diagnostic.STAGE / ('native-run-'+token)

    def test_missing_malformed_changed_noncanonical_reservation(self):
        for raw in (b'{"PRIVATE_CANARY":', b'{}', b'null', b'{"schema":1,"schema":1}'):
            replay = ProtectedReplay()
            path = replay.rows[0]['directory']+'/reservation.json'
            replay.docs[path] = raw
            self.assert_private_refusal(replay.replay)

    def test_duplicate_and_malformed_directory_names_refuse(self):
        for malformed in ('native-run-PRIVATE_CANARY', 'native-run-'+'a'*31, 'native-run-'+'A'*32):
            replay = ProtectedReplay()
            replay.directories.append(replay.root / diagnostic.STAGE / malformed)
            self.assert_private_refusal(replay.replay)
        replay = ProtectedReplay()
        replay.directories.append(replay.directories[-1])
        self.assert_private_refusal(replay.replay)

    def test_reservation_type_equivalence_cannot_replace_canonical_bytes(self):
        # Isolate the stronger guard so inherited schema checks cannot mask it.
        for field, replacement in (('schema', True), ('native_eligible', 0)):
            replay = ProtectedReplay()
            document = deepcopy(replay.rows[-1]['files']['reservation.json']['document'])
            document[field] = replacement
            path = replay.rows[-1]['directory']+'/reservation.json'
            replay.docs[path] = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
            with patch.object(current, 'pin_bytes', side_effect=replay.read), \
                    patch.object(Path, 'glob', side_effect=lambda *args: iter(replay.directories)), \
                    patch('infra.live_recovery_drill.PrivateDirectory') as private:
                private.return_value.pin = replay.pin
                with ExitStack() as pins, self.assertRaises(p.ProvenanceUnavailable):
                    p._reservations(replay.root, pins, Mock(), replay.rows, current, diagnostic)

    def test_discovery_overflow_reads_at_most257_entries(self):
        replay = ProtectedReplay()
        visited = []

        def discovery(*args):
            for n in range(1000):
                visited.append(n)
                yield replay.directories[0]
        with patch.object(Path, 'glob', side_effect=discovery), \
                patch.object(current, 'pin_bytes', side_effect=replay.read), \
                patch.object(controller, '_postflight_originals', return_value=deepcopy(replay.rows)):
            prepared = json.loads(Path(diagnostic.receipt_path('prepare')).read_text())['preparation']
            self.assert_private_refusal(lambda: p.preserved_originals(replay.root, ExitStack(), Mock(), prepared))
        self.assertEqual(len(visited), 257)

    def test_protected_directory_failure_is_fixed_private_refusal(self):
        replay = ProtectedReplay()
        with patch.object(current, 'pin_bytes', side_effect=replay.read), \
                patch.object(Path, 'glob', side_effect=lambda *args: iter(replay.directories)), \
                patch('infra.live_recovery_drill.PrivateDirectory') as private:
            private.return_value.pin.side_effect = RuntimeError('PRIVATE_DIRECTORY_CANARY')
            prepared = json.loads(Path(diagnostic.receipt_path('prepare')).read_text())['preparation']
            self.assert_private_refusal(lambda: p.preserved_originals(replay.root, ExitStack(), Mock(), prepared))

    def test_import_inert_no_inherited_module_or_io(self):
        original_import = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name.startswith('infra'):
                self.fail('Inherited import during module load')
            return original_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=guarded), \
                patch('builtins.open', side_effect=AssertionError('Import I/O')):
            importlib.reload(p)


if __name__ == '__main__':
    unittest.main()
