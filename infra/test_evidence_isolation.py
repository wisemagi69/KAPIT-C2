"""Pure OS-boundary unit tests; mocks never establish actual child denials."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infra import evidence_isolation as iso


class FakeWindows:
    """Exercise actual launch ordering up to a deliberately refused job assignment."""
    def __init__(self, token_denied=False):
        self.calls = []
        self.next_handle = 100
        self.token_denied = token_denied
        def pipe(read, write, attributes, size):
            self.next_handle += 2
            c.cast(read, c.POINTER(w.HANDLE))[0] = self.next_handle
            c.cast(write, c.POINTER(w.HANDLE))[0] = self.next_handle + 1
            return True
        def initialize(pointer, count, flags, size):
            c.cast(size, c.POINTER(c.c_size_t))[0] = 256
            return pointer is not None
        def attribute(pointer, flags, key, value, size, *unused):
            if key == 0x20009:
                caps = c.cast(value, c.POINTER(iso.SECURITY_CAPABILITIES)).contents
                assert caps.Count == 0 and not caps.Capabilities
            if key == 0x20002:
                assert size == c.sizeof(w.HANDLE) * 2
            self.calls.append(('attribute', key))
            return True
        def create(app, command, p, t, inherit, flags, environment, cwd, startup, process):
            self.calls.append(('create', flags, bool(inherit)))
            info = c.cast(process, c.POINTER(iso.PROCESS_INFORMATION)).contents
            info.process, info.thread, info.pid, info.tid = 501, 502, 503, 504
            return True
        def assign(job, process):
            self.calls.append(('assign',))
            return False
        self.stopped = False
        def terminate(*args):
            self.stopped = True
            self.calls.append(('terminate_owned_suspended',))
            return True
        def exit_code(handle, pointer):
            c.cast(pointer, c.POINTER(w.DWORD))[0] = 72 if self.stopped else 259
            return True
        self.k = SimpleNamespace(CreatePipe=pipe, SetHandleInformation=lambda *a: True,
            InitializeProcThreadAttributeList=initialize, UpdateProcThreadAttribute=attribute,
            CreateProcessW=create, AssignProcessToJobObject=assign,
            ResumeThread=lambda *a: self.calls.append(('resume',)) or 1,
            TerminateProcess=terminate,
            TerminateJobObject=lambda *a: self.calls.append(('terminate_job',)) or True,
            WaitForSingleObject=lambda *a: 0 if self.stopped else 258,
            GetExitCodeProcess=exit_code, DeleteProcThreadAttributeList=lambda *a: None)
    def job(self):
        self.calls.append(('job',))
        return 601
    def close(self, handle):
        pass
    def require(self, result, code):
        if not result:
            iso.fail(code)
    def token_proof(self, process, sid):
        self.calls.append(('token_proof',))
        if self.token_denied:
            iso.fail('LPAC_UNVERIFIED')


class EvidenceIsolationTests(unittest.TestCase):
    def test_no_caller_quota_or_configuration_can_enable_validation(self):
        with patch.object(iso, 'Windows', side_effect=AssertionError('NO_OS_CALL')):
            for request in ({}, {'quota': True}, {'disk_quota': 'VERIFIED', 'trusted': True}):
                result = iso.run_isolated(request, hard_quota=True)
                self.assertEqual(result['code'], 'QUOTA_UNAVAILABLE')
                self.assertEqual(result['validators_launched'], 0)
                self.assertEqual(result['validation'], 'CLOSED')

    def test_kernel_job_limits_exclude_breakaway_and_include_all_hard_limits(self):
        value = iso.job_limits()
        self.assertEqual(value.Basic.ActiveProcesses, 1)
        self.assertEqual(value.Basic.Flags & (0x800 | 0x1000), 0)
        for flag in (0x2000, 0x8, 0x100, 0x200, 0x2, 0x4):
            self.assertTrue(value.Basic.Flags & flag)
        self.assertEqual(value.Basic.ProcessTime, 10_000_000)
        self.assertEqual(value.Basic.JobTime, 10_000_000)
        self.assertEqual(value.ProcessMemory, 128 * 1024 * 1024)
        self.assertEqual(value.JobMemory, value.ProcessMemory)

    def test_extended_create_is_suspended_unicode_and_no_window(self):
        for flag in (0x4, 0x80000, 0x400, 0x08000000):
            self.assertTrue(iso.CREATE_FLAGS & flag)
        self.assertFalse(iso.CREATE_FLAGS & 0x01000000)

    def test_no_db_python_pip_or_proxy_environment_inherited(self):
        with patch.dict(os.environ, {'KAPIT_DB_PASSWORD': 'PRIVATE_ENV_CANARY', 'KAPIT_SOURCE_KEY': 'PRIVATE_ENV_CANARY',
                'PGSERVICE': 'PRIVATE_ENV_CANARY', 'PYTHONPATH': 'PRIVATE_ENV_CANARY', 'HTTP_PROXY': 'PRIVATE_ENV_CANARY'}):
            env = iso._probe_environment(iso.AREA / 'synthetic')
        self.assertNotIn('PRIVATE_ENV_CANARY', json.dumps(env))
        self.assertEqual(env['TEMP'], str(iso.AREA / 'synthetic'))
        self.assertEqual(set(env), {'SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOME', 'COMPLUS_EnableDiagnostics'})

    def test_job_assignment_failure_never_resumes_and_stops_its_suspended_child(self):
        iso.AREA.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=iso.AREA) as folder:
            exe = Path(folder) / 'probe.exe'
            exe.write_bytes(b'fixed-benign-placeholder')
            api = FakeWindows()
            with self.assertRaisesRegex(iso.IsolationError, '^JOB_ASSIGNMENT_UNAVAILABLE$'):
                iso._launch_probe(api, exe, hashlib.sha256(exe.read_bytes()).hexdigest(), c.c_void_p(1), [], Path(folder), 1, 'baseline')
            calls = [item[0] for item in api.calls]
            self.assertLess(calls.index('create'), calls.index('token_proof'))
            self.assertLess(calls.index('token_proof'), calls.index('assign'))
            self.assertNotIn('resume', calls)
            self.assertIn('terminate_owned_suspended', calls)
            self.assertEqual([x[1] for x in api.calls if x[0] == 'attribute'], [0x20009, 0x20002, 0x2000f])

    def test_token_failure_prevents_job_assignment_and_resume(self):
        with TemporaryDirectory(dir=iso.AREA) as folder:
            exe = Path(folder) / 'probe.exe'
            exe.write_bytes(b'fixed-benign-placeholder')
            api = FakeWindows(token_denied=True)
            with self.assertRaisesRegex(iso.IsolationError, '^LPAC_UNVERIFIED$'):
                iso._launch_probe(api, exe, hashlib.sha256(exe.read_bytes()).hexdigest(), c.c_void_p(1), [], Path(folder), 1, 'baseline')
            self.assertNotIn(('assign',), api.calls)
            self.assertNotIn(('resume',), api.calls)
            self.assertIn(('terminate_owned_suspended',), api.calls)

    def test_changed_probe_binary_fails_before_any_job_or_child(self):
        with TemporaryDirectory(dir=iso.AREA) as folder:
            exe = Path(folder) / 'probe.exe'
            exe.write_bytes(b'PRIVATE_BINARY_CANARY')
            api = FakeWindows()
            with self.assertRaisesRegex(iso.IsolationError, '^PROBE_BINARY_CHANGED$'):
                iso._launch_probe(api, exe, '0' * 64, c.c_void_p(1), [], Path(folder), 1, 'baseline')
            self.assertEqual(api.calls, [])

    def test_unknown_probe_mode_cannot_become_generic_command_surface(self):
        with TemporaryDirectory(dir=iso.AREA) as folder:
            exe = Path(folder) / 'probe.exe'
            exe.write_bytes(b'fixed-benign-placeholder')
            api = FakeWindows()
            with self.assertRaisesRegex(iso.IsolationError, '^PROBE_MODE_REFUSED$'):
                iso._launch_probe(api, exe, hashlib.sha256(exe.read_bytes()).hexdigest(), c.c_void_p(1), [], Path(folder), 1, 'arbitrary')
            self.assertEqual(api.calls, [])

    def test_outside_and_reparse_path_refused(self):
        with self.assertRaisesRegex(iso.IsolationError, '^PATH_REFUSED$'):
            iso.path_checked(iso.ROOT.parent / 'outside')
        with TemporaryDirectory(dir=iso.AREA) as folder:
            original = Path.lstat
            target = Path(folder)
            def replaced(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                return SimpleNamespace(st_mode=result.st_mode, st_file_attributes=0x400) if path == target else result
            with patch.object(Path, 'lstat', replaced), self.assertRaisesRegex(iso.IsolationError, '^PATH_REFUSED$'):
                iso.path_checked(target)

    def test_api_probe_does_not_claim_mocked_child_or_quota_success(self):
        def missing_profile(sid):
            iso.fail('APPCONTAINER_PROFILE_UNAVAILABLE')
        fake = SimpleNamespace(fresh_sid=lambda: 1, job=lambda: 2, close=lambda *a: None,
                               a=SimpleNamespace(FreeSid=lambda *a: None), require_profile=missing_profile)
        with patch.object(iso, 'Windows', return_value=fake):
            result = iso.capability_probe()
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertEqual(result['code'], 'APPCONTAINER_PROFILE_UNAVAILABLE')
        self.assertEqual(result['derive_sid'], 'VERIFIED')
        self.assertEqual(result['job_configuration'], 'VERIFIED')
        for key in ('lpac_child', 'network', 'filesystem', 'handles'):
            self.assertEqual(result[key], 'NOT_PROBED')
        self.assertEqual(result['disk_quota'], 'UNAVAILABLE')
        self.assertEqual(result['validators_launched'], 0)

    def test_missing_profile_guard_is_readonly_and_fails_with_fixed_code(self):
        api = iso.Windows.__new__(iso.Windows)
        api.sid_text = lambda sid: 'synthetic-sid'
        api.u = SimpleNamespace(GetAppContainerFolderPath=lambda *args: -2147024894)
        api.ole = SimpleNamespace(CoTaskMemFree=lambda *args: self.fail('NO_ALLOCATION'))
        with self.assertRaisesRegex(iso.IsolationError, '^APPCONTAINER_PROFILE_UNAVAILABLE$'):
            api.require_profile(c.c_void_p(1))

    def test_unexpected_existing_profile_never_adopted_and_allocated_path_freed(self):
        api = iso.Windows.__new__(iso.Windows)
        api.sid_text = lambda sid: 'synthetic-sid'
        buffer = c.create_unicode_buffer('UNTRUSTED_PROFILE_PATH_CANARY')
        freed = []
        def lookup(sid, output):
            c.cast(output, c.POINTER(w.LPWSTR))[0] = c.cast(buffer, w.LPWSTR)
            return 0
        api.u = SimpleNamespace(GetAppContainerFolderPath=lookup)
        api.ole = SimpleNamespace(CoTaskMemFree=lambda pointer: freed.append(bool(pointer)))
        with self.assertRaisesRegex(iso.IsolationError, '^APPCONTAINER_PROFILE_OWNERSHIP_UNVERIFIED$'):
            api.require_profile(c.c_void_p(1))
        self.assertEqual(freed, [True])

    def test_profile_refusal_precedes_directory_compiler_listener_and_child(self):
        freed = []
        def missing_profile(sid):
            iso.fail('APPCONTAINER_PROFILE_UNAVAILABLE')
        fake = SimpleNamespace(fresh_sid=lambda: 1, require_profile=missing_profile,
                               close=lambda *args: None, a=SimpleNamespace(FreeSid=lambda sid: freed.append(sid)))
        with (patch.object(iso, 'Windows', return_value=fake), patch.object(iso.Path, 'mkdir', side_effect=AssertionError('NO_FILES')),
                patch.object(iso.subprocess, 'run', side_effect=AssertionError('NO_COMPILER')),
                patch.object(iso.socket, 'socket', side_effect=AssertionError('NO_NETWORK')),
                patch.object(iso, '_launch_probe', side_effect=AssertionError('NO_CHILD'))):
            result = iso.benign_probe()
        self.assertEqual(result['code'], 'APPCONTAINER_PROFILE_UNAVAILABLE')
        self.assertEqual(result['validators_launched'], 0)
        self.assertEqual(result['benign_probes_completed'], 0)
        self.assertEqual(result['validation_receipt'], 'NONE')
        self.assertIsNone(result['run_id'])
        self.assertEqual(freed, [1])

    def test_arbitrary_os_exception_redacted_without_claimed_control_success(self):
        with patch.object(iso, 'Windows', side_effect=RuntimeError('PRIVATE_EXCEPTION_CANARY')):
            result = iso.capability_probe()
        self.assertNotIn('PRIVATE_EXCEPTION_CANARY', json.dumps(result))
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertEqual(result['lpac_child'], 'NOT_PROBED')

    def test_fixed_probe_is_nonimage_and_contains_no_profile_creation_api(self):
        source = Path(iso.__file__).read_text(encoding='utf-8')
        self.assertNotIn('CreateAppContainerProfile', source)
        self.assertNotIn('DeleteAppContainerProfile', source)
        self.assertIn('new byte[]{1,2,3,4}', iso.PROBE_SOURCE)
        self.assertNotIn('HttpClient', iso.PROBE_SOURCE)

    def test_failed_termination_dominates_original_job_assignment_refusal(self):
        with TemporaryDirectory(dir=iso.AREA) as folder:
            exe = Path(folder) / 'probe.exe'
            exe.write_bytes(b'fixed-benign-placeholder')
            api = FakeWindows()
            api.k.TerminateProcess = lambda *args: False
            with self.assertRaisesRegex(iso.IsolationError, '^OWNED_CHILD_STOP_UNCONFIRMED$'):
                iso._launch_probe(api, exe, hashlib.sha256(exe.read_bytes()).hexdigest(), c.c_void_p(1), [], Path(folder), 1, 'baseline')
            self.assertNotIn(('resume',), api.calls)

    def test_cleanup_timeout_still_active_and_unknown_job_never_claim_stop(self):
        process = iso.PROCESS_INFORMATION()
        process.process = 501
        for fault in ('timeout', 'still_active', 'job_active', 'job_query', 'termination'):
            api = FakeWindows()
            def query(job, kind, pointer, size, returned, fault=fault):
                if fault == 'job_query':
                    return False
                c.cast(pointer, c.POINTER(iso.ACCOUNTING)).contents.ActiveProcesses = 1 if fault == 'job_active' else 0
                return True
            def terminate(*args, fault=fault):
                api.stopped = True
                return fault != 'termination'
            api.k.QueryInformationJobObject = query
            api.k.TerminateJobObject = terminate
            if fault == 'timeout':
                api.k.WaitForSingleObject = lambda *args: 258
            if fault == 'still_active':
                def code(handle, pointer):
                    c.cast(pointer, c.POINTER(w.DWORD))[0] = 259
                    return True
                api.k.GetExitCodeProcess = code
            with self.subTest(fault=fault), self.assertRaisesRegex(iso.IsolationError, '^OWNED_CHILD_STOP_UNCONFIRMED$'):
                iso._stop_owned(api, process, 601, True)

    def test_already_exited_owned_child_verified_without_spurious_termination(self):
        process = iso.PROCESS_INFORMATION()
        process.process = 501
        api = FakeWindows()
        api.stopped = True
        api.k.TerminateProcess = lambda *args: self.fail('ALREADY_STOPPED')
        iso._stop_owned(api, process, None, False)


if __name__ == '__main__':
    unittest.main()
