"""Pure replay guard tests; actual installation is a separate explicit operator run."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from infra import reproduce_python as replay


class PythonReplayTests(unittest.TestCase):
    def temporary(self):
        return TemporaryDirectory(dir=replay.AREA)

    def test_actual_publisher_manifest_lock_and_twelve_archive_bytes_match(self):
        rows = replay.manifest()
        self.assertEqual(len(rows), 12)
        self.assertEqual(sum(r['role'] == 'application' for r in rows), 11)
        replay.verify_inputs(rows)

    def test_changed_archive_is_denied_without_reflecting_bytes(self):
        with self.temporary() as folder:
            path = Path(folder) / 'archive.whl'
            original = b'expected'
            path.write_bytes(b'PRIVATE_ARCHIVE_CANARY')
            with self.assertRaisesRegex(replay.ReplayError, '^HASH_MISMATCH$'):
                replay.read_fixed(path, 100, hashlib.sha256(original).hexdigest())

    def test_missing_extra_wrong_version_and_duplicate_installed_closure_denied(self):
        expected = [[k, v] for k, v in {**replay.EXPECTED, 'pip': '26.0.1'}.items()]
        replay.verify_closure(json.dumps(expected))
        for rows in (expected[:-1], expected + [['unexpected', '1']],
                     [[k, '0' if k == 'django' else v] for k, v in expected],
                     expected[:-1] + [expected[0]], [['PRIVATE_CANARY']]):
            with self.subTest(shape=len(rows)), self.assertRaisesRegex(replay.ReplayError, '^CLOSURE_MISMATCH$'):
                replay.verify_closure(json.dumps(rows))

    def test_missing_extra_and_duplicate_manifest_application_rows_denied(self):
        baseline = json.loads(replay.PROVENANCE.read_text())
        cases = [baseline['artifacts'][:-1], baseline['artifacts'] + [baseline['artifacts'][0]],
                 [baseline['artifacts'][0], *baseline['artifacts'][2:], baseline['artifacts'][0]]]
        with self.temporary() as folder:
            path = Path(folder) / 'manifest.json'
            for rows in cases:
                raw = json.dumps({**baseline, 'artifacts': rows}).encode()
                path.write_bytes(raw)
                with patch.object(replay, 'PROVENANCE', path), patch.object(replay, 'PROVENANCE_SHA256', hashlib.sha256(raw).hexdigest()):
                    with self.assertRaisesRegex(replay.ReplayError, '^CLOSURE_MISMATCH$'):
                        replay.manifest()

    def test_manifest_tampering_fails_frozen_digest_before_parse(self):
        with self.temporary() as folder:
            path = Path(folder) / 'manifest.json'
            path.write_text('{"PRIVATE_MANIFEST_CANARY":true}')
            with patch.object(replay, 'PROVENANCE', path):
                with self.assertRaisesRegex(replay.ReplayError, '^HASH_MISMATCH$'):
                    replay.manifest()

    def test_shared_lock_must_match_generated_full_closure_exactly(self):
        with self.temporary() as folder:
            path = Path(folder) / 'lock.txt'
            path.write_bytes(replay.lock_bytes(replay.manifest()).replace(b'psycopg[binary]', b'psycopg'))
            with patch.object(replay, 'LOCK', path), self.assertRaisesRegex(replay.ReplayError, '^LOCK_MISMATCH$'):
                replay.verify_inputs(replay.manifest())

    def test_missing_or_additional_wheelhouse_file_denied_before_install(self):
        with self.temporary() as folder:
            area = Path(folder)
            house = area / 'wheelhouse'
            house.mkdir()
            for extra in (False, True):
                if extra:
                    (house / 'unexpected.whl').write_bytes(b'PRIVATE_EXTRA_CANARY')
                with patch.object(replay, 'AREA', area), self.assertRaisesRegex(replay.ReplayError, '^WHEELHOUSE_MISMATCH$'):
                    replay.verify_inputs(replay.manifest())

    def test_outside_path_directory_and_hardlink_refused(self):
        with self.assertRaisesRegex(replay.ReplayError, '^PATH_REFUSED$'):
            replay.checked(replay.ROOT.parent / 'outside')
        with self.temporary() as folder:
            with self.assertRaisesRegex(replay.ReplayError, '^INPUT_REFUSED$'):
                replay.read_fixed(Path(folder), 100)
            source, alias = Path(folder) / 'source', Path(folder) / 'alias'
            source.write_bytes(b'public-fixture')
            try:
                os.link(source, alias)
            except OSError:
                self.skipTest('HARDLINK_UNAVAILABLE')
            with self.assertRaisesRegex(replay.ReplayError, '^INPUT_REFUSED$'):
                replay.read_fixed(alias, 100)

    def test_reparse_attribute_denied_before_file_read(self):
        with self.temporary() as folder:
            path = Path(folder)
            original = Path.lstat
            def lstat(value, *args, **kwargs):
                result = original(value, *args, **kwargs)
                if value == path:
                    from types import SimpleNamespace
                    return SimpleNamespace(st_mode=result.st_mode, st_file_attributes=0x400)
                return result
            with patch.object(Path, 'lstat', lstat), self.assertRaisesRegex(replay.ReplayError, '^PATH_REFUSED$'):
                replay.checked(path)

    def test_host_target_requires_regular_exact_runtime(self):
        replay.require_target()
        with patch.object(replay.platform, 'machine', return_value='ARM64'):
            with self.assertRaisesRegex(replay.ReplayError, '^TARGET_UNAVAILABLE$'):
                replay.require_target()
        with patch.object(replay.sysconfig, 'get_config_var', return_value=1):
            with self.assertRaisesRegex(replay.ReplayError, '^TARGET_UNAVAILABLE$'):
                replay.require_target()

    def test_child_identity_cannot_point_to_active_venv_or_wrong_version(self):
        with self.temporary() as folder:
            target = Path(folder)
            exe = target / 'venv/Scripts/python.exe'
            data = {'prefix': str(target / 'venv'), 'base': replay.sys.base_prefix, 'executable': str(exe),
                    'version': [3, 14, 4], 'implementation': 'CPython', 'platform': 'win32',
                    'machine': 'AMD64', 'pointer_bytes': 8, 'gil_disabled': 0}
            replay.verify_identity(json.dumps(data), target, exe)
            for key, value in [('prefix', str(replay.ROOT / '.cache/m1-runtime/venv')),
                               ('version', [3, 14, 3]), ('gil_disabled', 1), ('executable', replay.sys.executable)]:
                with self.subTest(key=key), self.assertRaisesRegex(replay.ReplayError, '^CHILD_IDENTITY_MISMATCH$'):
                    replay.verify_identity(json.dumps({**data, key: value}), target, exe)

    def test_poisoned_pip_python_proxy_env_excluded_and_paths_isolated(self):
        with self.temporary() as folder, patch.dict(os.environ, {'PIP_INDEX_URL': 'PRIVATE_ENV_CANARY',
                'PYTHONPATH': 'PRIVATE_ENV_CANARY', 'HTTP_PROXY': 'PRIVATE_ENV_CANARY', 'PYTHONHOME': 'PRIVATE_ENV_CANARY'}):
            env = replay.clean_environment(Path(folder))
            self.assertNotIn('PRIVATE_ENV_CANARY', json.dumps(env))
            self.assertEqual(env['PIP_CONFIG_FILE'], os.devnull)
            self.assertEqual(env['TEMP'], str(Path(folder) / 'tmp'))
            self.assertEqual(env['VIRTUAL_ENV'], str(Path(folder) / 'venv'))

    def test_target_exclusive_creation_and_marker_drift_denied(self):
        with self.temporary() as folder, patch.object(replay, 'AREA', Path(folder)):
            target, marker = replay.reserve()
            replay.verify_owner(target, marker)
            (target / 'owner.json').write_text('{"owner":"PRIVATE_OWNER_CANARY"}')
            with self.assertRaisesRegex(replay.ReplayError, '^TARGET_OWNER_CHANGED$'):
                replay.verify_owner(target, marker)
            with patch.object(replay.uuid, 'uuid4') as generate:
                generate.return_value.hex = target.name
                with self.assertRaises(FileExistsError):
                    replay.reserve()

    def test_subprocess_permission_failure_output_and_errors_redacted(self):
        with patch.object(replay.subprocess, 'run', side_effect=PermissionError('PRIVATE_PROCESS_CANARY')):
            with self.assertRaisesRegex(replay.ReplayError, '^SUBPROCESS_UNAVAILABLE$'):
                replay.child(['fixed-program'], {})
        with patch.object(replay.subprocess, 'run') as run:
            run.return_value.returncode = 1
            run.return_value.stdout = b'PRIVATE_PROCESS_CANARY'
            with self.assertRaisesRegex(replay.ReplayError, '^CHILD_CHECK_FAILED$'):
                replay.child(['fixed-program'], {})
            self.assertIs(run.call_args.kwargs['stderr'], replay.subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs['timeout'], 180)
            self.assertEqual(run.call_args.args[0], ['fixed-program', '-B'])

    def test_prepare_never_creates_venv_or_child(self):
        with patch.object(replay.venv.EnvBuilder, 'create', side_effect=AssertionError('NO_CREATE')), patch.object(replay, 'child', side_effect=AssertionError('NO_CHILD')):
            result = replay.replay(False)
        self.assertEqual(result['status'], 'VERIFIED_NOT_EXECUTED')
        self.assertEqual(result['application'], 'UNTOUCHED')


if __name__ == '__main__':
    unittest.main()
