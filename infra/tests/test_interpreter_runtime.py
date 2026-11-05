"""Pure controller regressions: no Docker, protected inputs or native execution."""
from copy import deepcopy
from contextlib import ExitStack, nullcontext
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from infra import evidence_interpreter_runtime as refresh


def chain():
    return {'compiler_image': refresh.COMPILER, 'main_library_sha256': refresh.LIBRARY,
        'lock_sha256': '1' * 64, 'runtime_json_sha256': '2' * 64,
        'signature_generation': '3' * 64, 'package_sha256': '4' * 64}


def built():
    return dict(chain(), schema=1, scope='PUBLIC_FRESH_RUNTIME_BUILD_NOT_NATIVE_PROOF', status='VERIFIED',
        native_eligible=False, private_input_allowed=False, control_state_modified=False,
        runtime_image_built=True, reason='EXIT', exit=0, cli_started=True, cli_reaped=True,
        threads_joined=True, pipes_closed=True, pins_closed=True, context=refresh.CONTEXT,
        config_digest='sha256:' + '5' * 64, reservation='6' * 32,
        tag='kapit-public-native-runtime:' + '6' * 32, total_seconds=1)


def actual_image():
    from infra import evidence_native_runtime as runtime
    return {'Id': 'sha256:' + '7' * 64, 'Os': 'linux', 'Architecture': 'amd64',
        'RepoTags': [built()['tag']], 'RootFS': {'Type': 'layers', 'Layers': ['sha256:' + '8' * 64]},
        'Descriptor': {'digest': 'sha256:' + '7' * 64, 'annotations': {'config.digest': built()['config_digest']}},
        'Config': {'Env': [key + '=' + value for key, value in runtime.IMAGE_ENV.items()],
            'Entrypoint': [runtime.ENTRYPOINT, '-I', '-B', '-m', runtime.MODULE],
            'User': '65532:65532', 'WorkingDir': '/scratch', 'Cmd': [],
            'Labels': {'org.kapit.owner': refresh.OWNER, 'org.kapit.reservation': built()['reservation']}}}


class ParsingTests(unittest.TestCase):
    def test_duplicate_keys_nonfinite_and_depth_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'[]',
                    b'{"x":' + b'[' * 22 + b'0' + b']' * 22 + b'}', b'x' * 262145):
            with self.subTest(raw=raw[:30]), self.assertRaises(refresh.RefreshUnavailable):
                refresh.document(raw)

    def test_valid_document(self):
        self.assertEqual(refresh.document(b'{"ok":true,"seconds":1.5}'), {'ok': True, 'seconds': 1.5})

    def test_old_compiler_wrong_generation_or_context_refuse(self):
        package = dict(chain(), schema=1, native_eligible=False, control_state_modified=False,
                       directory=refresh.CONTEXT)
        for key, value in (('compiler_image', 'sha256:' + 'a' * 64),
                           ('signature_generation', '0' * 64), ('signature_generation', 'bad'),
                           ('main_library_sha256', '9' * 64), ('directory', '../ctx5'), ('native_eligible', True)):
            with self.subTest(key=key, value=value), self.assertRaises(refresh.RefreshUnavailable):
                refresh.binding(dict(package, **{key: value}), b'{}')

    def test_context_names_and_rows_bounded(self):
        good = {'Dockerfile': {'bytes': 1, 'sha256': 'a' * 64}}
        refresh.context_files(good)
        for name in ('../Dockerfile', '/Dockerfile', 'C:/Dockerfile', './Dockerfile', 'closure//lib/a',
                     'closure/lib/../../escape', 'closure\\lib\\x', 'kapit_evidence/unknown.py'):
            with self.subTest(name=name), self.assertRaises(refresh.RefreshUnavailable):
                refresh.context_files(dict(good, **{name: {'bytes': 1, 'sha256': 'a' * 64}}))
        for row in ({'bytes': True, 'sha256': 'a' * 64}, {'bytes': 1, 'sha256': 'X' * 64},
                    {'bytes': 257 * 1024**2, 'sha256': 'a' * 64}, {'bytes': 1, 'sha256': 'a' * 64, 'link': 'x'}):
            with self.subTest(row=row), self.assertRaises(refresh.RefreshUnavailable):
                refresh.context_files({'Dockerfile': row})

    def test_build_chain_and_cleanup_refuse(self):
        refresh.validate_build(built(), chain())
        mutations = [('package_sha256', 'a' * 64), ('signature_generation', 'b' * 64),
            ('runtime_image_built', False), ('pins_closed', False), ('cli_reaped', False),
            ('threads_joined', False), ('pipes_closed', False), ('exit', True), ('total_seconds', 300),
            ('config_digest', 'not-an-id'), ('reservation', '../../old'), ('status', 'REFUSED'),
            ('exception_class', 'KeyboardInterrupt'), ('daemon_build_cancellation', 'UNCONFIRMED')]
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(refresh.RefreshUnavailable):
                refresh.validate_build(dict(built(), **{key: value}), chain())


class IdentityTests(unittest.TestCase):
    def test_uncertain_prior_suite_cannot_be_retried_with_new_uuid(self):
        path = refresh.ROOT / 'ai/state' / ('private-scanner-interpreter-suite-strict.json')
        with patch.object(Path, 'glob', return_value=[path]), \
             patch.object(refresh, 'pin_bytes', return_value=b'{"active_case":{"name":"strict"}}'):
            with self.assertRaises(refresh.RefreshUnavailable) as caught:
                refresh.prior_suites(refresh.ROOT, ExitStack(), object())
        self.assertEqual(caught.exception.code, 'PRIOR_SUITE_UNCONFIRMED')

    def test_actual_defaults_and_config_manifest_binding(self):
        self.assertEqual(refresh.image_document(actual_image(), built(), chain()), actual_image()['Id'])
        changes = [lambda x: x.update(Architecture='arm64'), lambda x: x.update(Os='windows'),
            lambda x: x['Config'].update(User='0'), lambda x: x['Config'].update(Volumes={'/data': {}}),
            lambda x: x['Config']['Labels'].update({'org.kapit.reservation': 'a' * 32}),
            lambda x: x['Descriptor']['annotations'].update({'config.digest': 'sha256:' + 'a' * 64}),
            lambda x: x['Descriptor'].update(digest='sha256:' + 'b' * 64),
            lambda x: x.update(RepoTags=['kapit-public-native-runtime:old'])]
        for change in changes:
            item = deepcopy(actual_image()); change(item)
            with self.assertRaises(Exception):
                refresh.image_document(item, built(), chain())

    def test_live_identity_rejects_wrong_immutable_image(self):
        with patch.object(refresh, 'tools', return_value=('docker', None, 'config', {})), \
             patch.object(refresh, 'pin_bytes', return_value=json.dumps(built()).encode()), \
             patch.object(refresh, 'call', return_value=(0, json.dumps([actual_image()]).encode(), b'', 'EXIT')):
            with self.assertRaises(refresh.RefreshUnavailable):
                refresh.identity(Path('x'), ExitStack(), object(), chain(), {}, expected='sha256:' + '9' * 64)

    def test_saved_image_live_generation_config_chain_must_equal(self):
        saved = dict(chain(), schema=1, scope='PUBLIC_FRESH_RUNTIME_IDENTITY_NOT_NATIVE_PROOF',
            status='VERIFIED', pins_closed=True, native_eligible=False, private_input_allowed=False,
            control_state_modified=False, compiler_image_id=refresh.COMPILER, image_id=actual_image()['Id'],
            config_digest=built()['config_digest'], build_sha256='a' * 64)
        def live(*args, **kwargs):
            args[4].update(image_id=actual_image()['Id'], config_digest='sha256:' + 'b' * 64)
        with patch.object(refresh, 'load_package', return_value=({}, chain())), \
             patch.object(refresh, 'pin_bytes', return_value=json.dumps(saved).encode()), \
             patch.object(refresh, 'identity', side_effect=live):
            with self.assertRaises(refresh.RefreshUnavailable):
                refresh.verified_image(Path('x'), ExitStack(), object())


class CleanupTests(unittest.TestCase):
    def mocked_build(self, *, iid=None, broken_reader=False):
        proc = MagicMock(); proc.returncode = 0; proc.poll.return_value = 0; proc.wait.return_value = 0
        proc.stdout = io.BytesIO(b'public build output'); proc.stderr = io.BytesIO()
        if broken_reader:
            proc.stdout = MagicMock(); proc.stdout.read1.side_effect = OSError()
        captured = {}
        with patch.object(refresh, 'tools', return_value=('docker', 'buildx', 'config', {'DOCKER_HOST': refresh.HOST})), \
             patch.object(refresh, 'call', return_value=(1, b'', b'No such image: random', 'EXIT')), \
             patch.object(refresh.shutil, 'disk_usage', return_value=MagicMock(free=refresh.INITIAL)), \
             patch.object(refresh, 'pin_bytes', return_value=iid or b'sha256:' + b'a' * 64 + b'\n'), \
             patch.object(refresh.subprocess, 'Popen', return_value=proc) as popen:
            refresh.build(refresh.ROOT, ExitStack(), object(), {}, chain(), captured)
        return captured, popen.call_args

    def test_owned_build_command_offline_and_success(self):
        result, called = self.mocked_build()
        self.assertTrue(result['runtime_image_built'])
        self.assertTrue(result['cli_reaped'] and result['threads_joined'] and result['pipes_closed'])
        self.assertIn('--network', called.args[0]); self.assertIn('none', called.args[0])
        self.assertIn('--pull=false', called.args[0]); self.assertIs(called.kwargs['shell'], False)
        self.assertEqual(called.kwargs['env'], {'DOCKER_HOST': refresh.HOST})

    def test_malformed_iid_and_reader_error_dominate_zero_exit(self):
        for kwargs, reason in (({'iid': b'not-a-digest'}, 'BUILD_OUTPUT_UNCONFIRMED'),
                               ({'broken_reader': True}, 'IO_FAILURE')):
            with self.subTest(kwargs=kwargs):
                result, _ = self.mocked_build(**kwargs)
                self.assertFalse(result['runtime_image_built'])
                self.assertEqual(result['reason'], reason)
                self.assertEqual(result['daemon_build_cancellation'], 'UNCONFIRMED_NO_GLOBAL_CLEANUP')

    def reason(self, **kw):
        args = dict(elapsed=1, free=refresh.INITIAL, iid='sha256:' + '1' * 64,
                    failed=False, overflow=False, cleanup=False)
        args.update(kw)
        return refresh.final_reason('EXIT', **args)

    def test_final_failure_priority_over_exit_zero(self):
        self.assertEqual(self.reason(), 'EXIT')
        self.assertEqual(self.reason(elapsed=300), 'WALL_LIMIT')
        self.assertEqual(self.reason(iid='bad'), 'BUILD_OUTPUT_UNCONFIRMED')
        self.assertEqual(self.reason(free=None), 'BUILD_OUTPUT_UNCONFIRMED')
        self.assertEqual(self.reason(free=refresh.FLOOR-1), 'LOW_SPACE')
        self.assertEqual(self.reason(failed=True), 'IO_FAILURE')
        self.assertEqual(self.reason(overflow=True), 'OUTPUT_LIMIT')
        self.assertEqual(self.reason(elapsed=301, iid=None, failed=True, overflow=True, cleanup=True),
                         'CLI_CLEANUP_UNCONFIRMED')

    def test_stop_reaps_joins_and_closes(self):
        process = MagicMock(); process.poll.return_value = 0; process.wait.return_value = 0
        thread = MagicMock(); thread.ident = 123; thread.is_alive.return_value = False
        self.assertEqual(refresh.stop_owned(process, [thread]), (True, True, True, False))
        thread.join.assert_called_once_with(timeout=5)
        process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()

    def test_failed_reader_prevents_blocking_stream_close(self):
        process = MagicMock(); process.poll.return_value = 0; process.wait.return_value = 0
        thread = MagicMock(); thread.ident = 123; thread.is_alive.return_value = True
        self.assertEqual(refresh.stop_owned(process, [thread]), (True, False, False, True))
        process.stdout.close.assert_not_called()

    def test_pipe_failure_is_uncertain_and_other_pipe_attempted(self):
        process = MagicMock(); process.poll.return_value = 0; process.wait.return_value = 0
        process.stdout.close.side_effect = OSError()
        self.assertEqual(refresh.stop_owned(process, []), (True, True, False, True))
        process.stderr.close.assert_called_once()

    def test_failed_stop_still_joins_all_readers(self):
        process = MagicMock(); process.poll.side_effect = OSError()
        threads = [MagicMock(), MagicMock()]
        for thread in threads:
            thread.ident = 3; thread.is_alive.return_value = False
        self.assertEqual(refresh.stop_owned(process, threads), (False, True, False, True))
        for thread in threads:
            thread.join.assert_called_once()

    def test_failed_thread_start_does_not_join_unstarted_thread(self):
        thread = MagicMock(); thread.ident = None; thread.is_alive.return_value = False
        self.assertEqual(refresh.stop_owned(None, [thread]), (True, True, True, False))
        thread.join.assert_not_called()

    def test_receipt_never_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            first = refresh.Receipt(path, {'status': 'REFUSED'}); first.close()
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                refresh.Receipt(path, {'status': 'VERIFIED'})
            self.assertEqual(path.read_bytes(), before)

    def execute_mock(self, close_error=False, deadline=False):
        from infra import evidence_interpreter_compile as compiler
        receipt = MagicMock(); pins = MagicMock()
        pins.enter_context.side_effect=lambda context:context.__enter__()
        if close_error:
            pins.close.side_effect = OSError()
        def fake_build(root, stack, api, package, binding, result):
            result.update(runtime_image_built=True, reason='EXIT', seconds=1, cli_started=True)
        clock = [0, 301, 302] if deadline else [0, 1, 2]
        with patch.object(refresh.os, 'name', 'nt'), patch.object(refresh, 'Receipt', return_value=receipt), \
             patch.object(refresh,'reviewed_constants'),patch.object(refresh,'prior_suites'), \
             patch.object(refresh,'pin_bytes',return_value=b''), \
             patch.object(compiler,'checked_inputs',return_value=nullcontext((object(),pins,MagicMock(),{}))), \
             patch.object(compiler,'live_originals'), \
             patch.object(refresh, 'ExitStack', return_value=pins), \
             patch('infra.evidence_tools.Windows', return_value=object()), \
             patch.object(refresh, 'load_package', return_value=({}, chain())), \
             patch.object(refresh, 'build', side_effect=fake_build), \
             patch.object(refresh.time, 'monotonic', side_effect=clock):
            with self.assertRaises(refresh.RefreshUnavailable):
                refresh.execute('build')
        return receipt.save.call_args.args[0]

    def test_final_handle_close_failure_overrides_build_success(self):
        result = self.execute_mock(close_error=True)
        self.assertEqual(result['status'], 'REFUSED')
        self.assertFalse(result['runtime_image_built'])
        self.assertEqual(result['reason'], 'CLI_CLEANUP_UNCONFIRMED')

    def test_deadline_after_close_overrides_build_success(self):
        result = self.execute_mock(deadline=True)
        self.assertEqual(result['status'], 'REFUSED')
        self.assertFalse(result['runtime_image_built'])
        self.assertEqual(result['reason'], 'WALL_LIMIT')


class SuiteTests(unittest.TestCase):
    def run_suite(self, name, *, per_case_chain=None, wrong_live_image=False, observed_generation=None,
                  cleanup='OWNED_CONTAINER_ABSENT_VERIFIED', interruption=False):
        from infra import evidence_native_attestation as probes
        from infra import evidence_native_runtime as runtime
        from infra import evidence_container as base
        from infra import evidence_container_native as public
        result = {'status': 'REFUSED'}; saved = []; calls = []; count = 0
        image = dict(chain(), image_id=actual_image()['Id'], config_digest=built()['config_digest'], build_sha256='a'*64)
        receipt = MagicMock(); receipt.path = refresh.ROOT / 'ai/state/current-owned.json'
        receipt.save.side_effect = lambda value: saved.append(deepcopy(value))
        def live(root, pins, api, current, target, *, expected=None):
            nonlocal count
            count += 1
            target.update(image)
            if wrong_live_image and count > 1:
                target['image_id'] = 'sha256:' + 'b' * 64
        def probe(candidate, case=None, *, resource_mode=None, **kwargs):
            calls.append((case, resource_mode, candidate.image_id, candidate.signature_generation))
            if interruption:
                raise KeyboardInterrupt()
            return {'candidate_image_id': candidate.image_id,
                'declared_signature_generation': observed_generation or candidate.signature_generation,
                'cleanup': cleanup}
        def fixture(candidate, case, **kwargs):
            value = probe(candidate, case, **kwargs)
            if cleanup == 'OWNED_CONTAINER_ABSENT_VERIFIED':
                value['cleanup'] = 'ALL_OWNED_CONTAINERS_ABSENT_VERIFIED'
            return value
        outcome = None
        with patch.object(refresh, 'observe_case_originals'), patch.object(refresh, 'prior_suites'), patch.object(refresh, 'verified_image', return_value=image), \
             patch.object(refresh, 'identity', side_effect=live), \
             patch.object(refresh, 'pin_bytes', return_value=base.canonical(public.startup_profile())), \
             patch.object(refresh, 'load_package', return_value=({}, per_case_chain or chain())), \
             patch.object(refresh.shutil, 'disk_usage', return_value=MagicMock(free=refresh.INITIAL)), \
             patch.object(probes, 'run_public_probe', side_effect=probe), \
             patch.object(probes, 'run_strict_probe', side_effect=lambda candidate, **kw: probe(candidate, 'strict', **kw)), \
             patch.object(probes, 'run_pcre_probe', side_effect=lambda candidate, **kw: probe(candidate, 'pcre', **kw)), \
             patch.object(runtime, 'run_fixture_pipeline', side_effect=fixture), patch('builtins.print'):
            try:
                refresh.suite(refresh.ROOT, ExitStack(), object(), {}, chain(), name, result, receipt, object())
            except BaseException as error:
                outcome = error
        return result, saved, calls, outcome

    def test_fixed_confinement_matrix_scan_then_decode(self):
        result, _, calls, error = self.run_suite('confinement')
        self.assertIsNone(error)
        names = sorted(('confinement', 'storage', 'x32', 'preopened_fd', 'shm_namespace'))
        self.assertEqual([(x['name'], x['mode']) for x in result['results']],
                         [(name, mode) for mode in ('scan', 'decode') for name in names])
        self.assertEqual(len(calls), 10)
        self.assertNotIn('active_case', result)

    def test_fixed_strict_pcre_and_six_pipeline_matrix(self):
        for name, expected in (('strict', ['strict']), ('pcre', ['pcre']), ('fixtures',
                ['png_clean', 'png_metadata', 'jpeg_clean', 'jpeg_metadata', 'png_malformed', 'png_eicar'])):
            result, _, calls, error = self.run_suite(name)
            with self.subTest(name=name):
                self.assertIsNone(error)
                self.assertEqual([row['name'] for row in result['results']], expected)
                self.assertTrue(all(row[2:] == (actual_image()['Id'], chain()['signature_generation']) for row in calls))

    def test_per_case_substituted_chain_refuses_before_native_call(self):
        result, _, calls, error = self.run_suite('strict', per_case_chain=dict(chain(), package_sha256='b'*64))
        self.assertIsInstance(error, refresh.RefreshUnavailable)
        self.assertEqual(calls, [])

    def test_per_case_live_wrong_image_refuses_before_native_call(self):
        result, _, calls, error = self.run_suite('strict', wrong_live_image=True)
        self.assertIsInstance(error, refresh.RefreshUnavailable)
        self.assertEqual(calls, [])

    def test_wrong_generation_or_unconfirmed_cleanup_does_not_record_success(self):
        for kwargs in ({'observed_generation': 'b'*64}, {'cleanup': 'UNCONFIRMED'}):
            result, saved, _, error = self.run_suite('strict', **kwargs)
            with self.subTest(kwargs=kwargs):
                self.assertIsInstance(error, refresh.RefreshUnavailable)
                self.assertEqual(result['results'], [])
                self.assertEqual(saved[-1]['active_case']['name'], 'strict')

    def test_interruption_preserves_active_case_in_original_receipt(self):
        result, saved, _, error = self.run_suite('strict', interruption=True)
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertEqual(result['results'], [])
        self.assertEqual(saved[-1]['active_case'], {'name': 'strict', 'mode': 'scan'})





"""Pure complete OCI byte-chain and parser denial tests; no Docker/host extraction."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import runpy
import time
import unittest

from infra import evidence_interpreter_oci as oci
M = vars(oci)
digest = lambda raw: 'sha256:' + hashlib.sha256(raw).hexdigest()
encode = lambda value: json.dumps(value, separators=(',', ':')).encode()


def fixture(*, reorder=False):
    payloads = [b'public-layer-' + str(index).encode() for index in range(13)]
    compressed = [gzip.compress(raw, mtime=0) for raw in payloads]
    config = {'os': 'linux', 'architecture': 'amd64', 'config': {'User': '65532:65532'},
              'rootfs': {'type': 'layers', 'diff_ids': [digest(raw) for raw in payloads]}}
    config_raw = encode(config)
    layers = [{'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip',
               'digest': digest(raw), 'size': len(raw)} for raw in compressed]
    if reorder: layers[0], layers[1] = layers[1], layers[0]
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
                'config': {'mediaType': 'application/vnd.docker.container.image.v1+json',
                           'digest': digest(config_raw), 'size': len(config_raw)}, 'layers': layers}
    manifest_raw = encode(manifest)
    actual = {'image_id': digest(manifest_raw), 'config_digest': digest(config_raw),
              'descriptor': {'digest': digest(manifest_raw), 'size': len(manifest_raw),
                             'mediaType': manifest['mediaType']},
              'config': config['config'], 'rootfs': {'Layers': config['rootfs']['diff_ids']}}
    rows, raw = {}, bytearray()
    for data in [manifest_raw, config_raw, *compressed]:
        rows['blobs/sha256/' + digest(data)[7:]] = {
            'bytes': len(data), 'offset': len(raw), 'sha256': digest(data)[7:], 'directory': False}
        raw.extend(data)
    metadata = {'archive_bytes': len(raw), 'archive_sha256': hashlib.sha256(raw).hexdigest()}
    return bytes(raw), rows, actual, metadata


class Oci(unittest.TestCase):
    def verify(self, data):
        raw, rows, actual, metadata = data
        return M['verify_archive'](io.BytesIO(raw), None, rows, actual, metadata, deadline=time.monotonic()+10)

    def test_complete_thirteen_layer_chain(self):
        result = self.verify(fixture())
        self.assertEqual(len(result['layers']), 13)
        self.assertEqual(result['status'], 'PASS')
        self.assertFalse(result['native_eligible'])
        self.assertFalse(result['filesystem_or_notices_audited'])

    def test_swapped_layers_fail_diff_id_order(self):
        with self.assertRaises(AssertionError): self.verify(fixture(reorder=True))

    def test_changed_archive_fails(self):
        raw, rows, actual, meta = fixture()
        with self.assertRaises(AssertionError): self.verify((raw[:-1]+bytes([raw[-1]^1]), rows, actual, meta))

    def test_wrong_config_identity_fails(self):
        raw, rows, actual, meta = fixture()
        actual['config_digest'] = 'sha256:'+'0'*64
        with self.assertRaises(AssertionError): self.verify((raw, rows, actual, meta))

    def test_missing_blob_fails(self):
        raw, rows, actual, meta = fixture()
        rows.pop(next(iter(rows)))
        with self.assertRaises(KeyError): self.verify((raw, rows, actual, meta))

    def test_duplicate_keys_refused(self):
        with self.assertRaises(AssertionError): M['document'](b'{"a":1,"a":2}')

    def test_nonfinite_json_refused(self):
        with self.assertRaises(ValueError): M['document'](b'{"a":NaN}')

    def test_second_gzip_member_refused(self):
        raw = gzip.compress(b'one')+gzip.compress(b'two')
        with self.assertRaises(AssertionError): M['gzip_digest'](io.BytesIO(raw), len(raw), deadline=time.monotonic()+10)

    def test_expansion_limit_and_deadline_refused(self):
        raw = gzip.compress(b'x'*4096)
        with self.assertRaises(AssertionError): M['gzip_digest'](io.BytesIO(raw), len(raw), deadline=time.monotonic()+10, maximum=4095)
        with self.assertRaises(AssertionError): M['gzip_digest'](io.BytesIO(raw), len(raw), deadline=time.monotonic()-1)


class InterpreterGuardTests(unittest.TestCase):
    def test_declared_unchanged_runtime_functions_match_frozen_ast(self):
        import ast
        raw=Path('infra/evidence_native_refresh_runtime.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'685271a88da7d6af12b6c26a99373420b9af0195d5aa7cd6953cea5c51259b17')
        old={n.name:n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        new={n.name:n for n in ast.parse(Path(refresh.__file__).read_text(encoding='utf-8')).body
             if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        names=('RefreshUnavailable','require','sha','document','pin_bytes','context_files','Receipt',
            'tools','call','stop_owned','final_reason','validate_build','image_document','identity','verified_image')
        for name in names:
            with self.subTest(name=name):self.assertEqual(ast.dump(old[name]),ast.dump(new[name]))
        # The sole build-body difference is the fixed new IID filename prefix.
        for node in ast.walk(new['build']):
            if isinstance(node,ast.Constant) and node.value == 'runtime-interpreter-':node.value='runtime-readback-'
        self.assertEqual(ast.dump(old['build']),ast.dump(new['build']))

    def test_oci_inventory_and_complete_verifier_match_frozen_ast(self):
        import ast
        raw=Path('ai/state/private-scanner-oci-audit-pcre.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'6f7dde728da1554d515187bc9ce735deda11759ab690c87fc76ea45371a5153b')
        originals={n.name:n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
        proof={n.name:n for n in ast.parse(Path('ai/state/private-scanner-refresh-oci-pcre.py').read_bytes()).body
               if isinstance(n,ast.FunctionDef)}
        new={n.name:n for n in ast.parse(Path(oci.__file__).read_text(encoding='utf-8')).body if isinstance(n,ast.FunctionDef)}
        self.assertEqual(ast.dump(originals['inventory']),ast.dump(new['inventory']))
        for name in ('document','gzip_digest','checked_layout','verify_archive'):
            with self.subTest(name=name):self.assertEqual(ast.dump(proof[name]),ast.dump(new[name]))
        # Normalize only the declared argument-based identity and fixed path.
        copied=new['acquire_archive'];copied.name='acquire';copied.args.args.pop()
        class Normalize(ast.NodeTransformer):
            def visit_Subscript(self,node):
                if isinstance(node.value,ast.Name) and node.value.id == 'actual_identity':
                    return ast.Name(id='IMAGE',ctx=ast.Load())
                return self.generic_visit(node)
            def visit_Constant(self,node):
                if node.value == 'ai/state/private-scanner-interpreter-runtime-image.json':
                    node.value='ai/state/private-scanner-runtime-image-pcre.json'
                return node
            def visit_Assert(self,node):
                if ast.dump(node.test) == ast.dump(ast.parse('expected == actual_identity',mode='eval').body):return None
                return self.generic_visit(node)
        copied=Normalize().visit(copied)
        self.assertEqual(ast.dump(originals['acquire']),ast.dump(copied))

    def test_oci_acquisition_or_close_failure_never_returns_verified(self):
        from infra import evidence_interpreter_compile as compiler
        from infra import live_recovery_drill
        for failed_acquire,failed_close in ((True,False),(False,True)):
            saved=[]; raw,rows,actual,metadata=fixture()
            class Receipt:
                def __init__(self,*args):self.stream=MagicMock(closed=False);self.closes=0
                def save(self,value):saved.append(deepcopy(value))
                def close(self):
                    self.closes+=1
                    if failed_close and self.closes == 1:raise OSError('close')
                    self.stream.closed=True
            api=MagicMock();api.pin.return_value=nullcontext(io.BytesIO(raw))
            def acquire(result,*args):
                if failed_acquire:raise RuntimeError('fixture acquisition')
                result.update(metadata)
            with patch.object(refresh,'reviewed_constants'),patch.object(refresh,'Receipt',Receipt),\
                 patch.object(oci,'RUNTIME_SHA256','a'*64),\
                 patch.object(compiler,'checked_inputs',return_value=nullcontext((api,None,MagicMock(),{}))),\
                 patch.object(compiler,'live_originals'),patch.object(refresh,'verified_image',return_value=actual),\
                 patch.object(refresh,'pin_bytes',return_value=json.dumps(actual).encode()),\
                 patch.object(oci,'acquire_archive',side_effect=acquire),\
                 patch.object(live_recovery_drill.PrivateDirectory,'pin',return_value=nullcontext()),\
                 patch.object(oci,'inventory',return_value=rows),\
                 self.assertRaises(refresh.RefreshUnavailable):oci.execute()
            self.assertEqual(saved[-1]['status'],'REFUSED')

    def test_unfilled_actual_pins_cannot_consume_runtime_or_oci_receipts(self):
        with patch.object(refresh,'COMPILER',None),patch.object(refresh,'Receipt',side_effect=AssertionError('must not reserve')):
            with self.assertRaises(refresh.RefreshUnavailable):refresh.execute('strict')
            with self.assertRaises(refresh.RefreshUnavailable):oci.execute()

    def test_each_placeholder_is_individually_closed(self):
        good={'COMPILER':'sha256:'+'a'*64,'LIBRARY':'b'*64,'PREPARATION_SHA256':'c'*64}
        for name in good:
            with patch.multiple(refresh,**dict(good,**{name:None})),self.assertRaises(refresh.RefreshUnavailable):
                refresh.reviewed_constants()

    def test_fixed_suite_paths_have_no_uuid_retry(self):
        source=Path(refresh.__file__).read_text(encoding='utf-8')
        self.assertIn("'ai/state/private-scanner-interpreter-suite-' + stage + '.json'",source)
        self.assertNotIn("stage + '-' + uuid.uuid4()",source)

    def test_failed_partial_empty_and_unknown_new_receipts_close_chain(self):
        path=refresh.ROOT/'ai/state/private-scanner-interpreter-suite-strict.json'
        for value in ({}, {'status':'REFUSED'}, {'status':'REFUSED','results':[]},
            {'status':'VERIFIED','pins_closed':True,'results':[]},
            {'status':'VERIFIED','pins_closed':True,'active_case':{'name':'strict'},'results':[]}):
            with patch.object(Path,'glob',return_value=[path]),\
                 patch.object(refresh,'pin_bytes',return_value=json.dumps(value).encode()),\
                 self.assertRaises(refresh.RefreshUnavailable):refresh.prior_suites(refresh.ROOT,ExitStack(),object())
        path=path.with_name('private-scanner-interpreter-suite-strict-forged.json')
        with patch.object(Path,'glob',return_value=[path]),self.assertRaises(refresh.RefreshUnavailable):
            refresh.prior_suites(refresh.ROOT,ExitStack(),object())

    def test_per_case_original_queries_use_pinned_same_clients_and_new_finite_budget(self):
        from infra.evidence_postcompile_diagnostic import Commands
        from infra import evidence_interpreter_compile as compiler
        parent=Commands('fixed-docker','fixed-config'); parent.count=63
        children=[]
        with patch.object(compiler,'live_originals',side_effect=lambda child:children.append(child) or MagicMock()):
            for _ in range(10):refresh.observe_case_originals(parent)
        self.assertEqual(parent.count,63)
        self.assertEqual(len(children),10)
        self.assertTrue(all(type(child) is Commands and child.count == 0 and
            child.docker == parent.docker and child.config == parent.config for child in children))
        parent.uncertain=True
        with self.assertRaises(refresh.RefreshUnavailable):refresh.observe_case_originals(parent)

    def test_oci_no_stale_image_global_or_source_loader_override(self):
        self.assertNotIn('IMAGE',vars(oci))
        source=Path(oci.__file__).read_text(encoding='utf-8')
        self.assertNotIn("loader['IMAGE']",source)
        self.assertNotIn('sha256:b20b3b',source)

    def test_oci_tar_links_and_duplicate_names_refuse(self):
        import tarfile
        for duplicate,link in ((True,False),(False,True)):
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w',format=tarfile.USTAR_FORMAT) as archive:
                info=tarfile.TarInfo('public');info.size=1
                archive.addfile(info,io.BytesIO(b'a'))
                if duplicate:archive.addfile(info,io.BytesIO(b'a'))
                if link:
                    info=tarfile.TarInfo('link');info.type=tarfile.SYMTYPE;info.linkname='public'
                    archive.addfile(info)
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'fixture.tar';path.write_bytes(data.getvalue())
                with self.assertRaises(AssertionError):oci.inventory(path)


if __name__ == '__main__':unittest.main()



