"""One fixed public diagnostic after a separately reviewed read-only preflight.

Import is inert. Root alone executes this controller; there are no CLI options.
The saved preflight supplies provenance, never permission to skip live checks.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import stat
import time

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = 'ai/state/private-scanner-continuation-diagnostic-pcre.json'
PREFLIGHT = 'infra/evidence_postcompile_preflight.py'
PREFLIGHT_SHA256 = '4697680bbfcccf25956194d4fc374fd238e1d31a056bf3d5136f83d08ec2985c'
FROZEN_CONTROLLER = 'infra/evidence_postcompile_diagnostic.py'
FROZEN_CONTROLLER_SHA256 = '5a24dbfa6de043730faa10c9ec3a8ba46fff8446d44fa82401977698dfda69ff'
SCOPE = 'PUBLIC_POSTCOMPILE_CONTINUATION_DIAGNOSTIC_ONLY'
OWN_STAGES = ('PREFLIGHT_PROVENANCE', 'DEDICATED_LOCK', 'PUBLIC_PROBE',
              'FINAL_ENGINE', 'FINAL_LIMITS', 'DEDICATED_LOCK_CLOSE', 'INPUT_CLOSE', 'FINAL_CLI')


def modules():
    from infra import evidence_postcompile_preflight as preflight
    from infra import evidence_postcompile_diagnostic as diagnostic
    from infra import evidence_native_refresh_runtime as refresh
    return preflight, diagnostic, refresh


def provenance(context):
    preflight, diagnostic, refresh = modules()
    diagnostic.require(type(PREFLIGHT_SHA256) is str and len(PREFLIGHT_SHA256) == 64,
                       'PREFLIGHT_SOURCE_NOT_REVIEWED')
    refresh.pin_bytes(ROOT, context.pins, context.api, PREFLIGHT, expected=PREFLIGHT_SHA256)
    refresh.pin_bytes(ROOT, context.pins, context.api, FROZEN_CONTROLLER,
                      expected=FROZEN_CONTROLLER_SHA256)
    raw = refresh.pin_bytes(ROOT, context.pins, context.api, preflight.PREFLIGHT_RECEIPT,
                            maximum=8192)
    preflight.validate_receipt(refresh.document(raw), PREFLIGHT_SHA256)


class SecurityAttributes(c.Structure):
    _fields_ = [('nLength', w.DWORD), ('lpSecurityDescriptor', c.c_void_p),
                ('bInheritHandle', w.BOOL)]


def lock_runtime():
    import msvcrt
    return msvcrt


def exact_lock(stream, path):
    """Check the same retained regular file, identity, single byte and link count."""
    _, diagnostic, _ = modules()
    from infra.evidence_tools import checked
    checked(path)
    observed = os.fstat(stream.fileno())
    before = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    diagnostic.require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
        and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        and identity(observed) == identity(before) and observed.st_size == 1,
        'LOCK_CHANGED')
    stream.seek(0)
    diagnostic.require(stream.read(2) == b'0', 'LOCK_CHANGED')
    stream.seek(0)


@contextmanager
def new_private_stream(path, api):
    """Create only a new file with its final DACL; never reopen to set its ACL."""
    _, diagnostic, _ = modules()
    from infra.evidence_tools import checked
    path = checked(path)
    descriptor = c.c_void_p()
    sids = list(dict.fromkeys(('S-1-5-18', api.user)))
    text = 'O:' + api.user + 'D:P' + ''.join('(A;;FA;;;' + sid + ')' for sid in sids)
    handle = None; descriptor_owned = False; fd = None; stream = None
    try:
        converted = api.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text, 1, c.byref(descriptor), None)
        descriptor_owned = bool(descriptor.value)
        diagnostic.require(bool(converted) and descriptor_owned, 'LOCK_SECURITY_DESCRIPTOR')
        attributes = SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        handle = api.k.CreateFileW(str(path), 0x20000 | 0x80000000 | 0x40000000,
            3, c.byref(attributes), 1, 0x00200000, None)
        if handle in (None, c.c_void_p(-1).value):
            handle = None
            diagnostic.require(c.get_last_error() in (80, 183), 'LOCK_CREATE_REFUSED')
            existing = True
        else:
            existing = False
            api.verify_acl(handle)
        # Free the creation descriptor before yielding, retaining the original
        # file handle. LocalFree uncertainty prevents any lock or runtime work.
        freed = api.k.LocalFree(descriptor)
        descriptor_owned = bool(freed)
        diagnostic.require(not freed, 'LOCK_DESCRIPTOR_CLOSE_UNCONFIRMED')
        if existing:
            yield None
        else:
            fd = lock_runtime().open_osfhandle(handle, os.O_BINARY | os.O_RDWR)
            handle = None  # CRT now owns the same original CreateFile handle.
            stream = os.fdopen(fd, 'r+b', buffering=0)
            fd = None
            diagnostic.require(stream.write(b'0') == 1, 'LOCK_WRITE_UNCONFIRMED')
            stream.flush(); os.fsync(stream.fileno())
            exact_lock(stream, path)
            yield stream
            exact_lock(stream, path)
    finally:
        try:
            if descriptor_owned:
                diagnostic.require(not api.k.LocalFree(descriptor), 'LOCK_DESCRIPTOR_CLOSE_UNCONFIRMED')
        finally:
            try:
                if stream is not None:
                    stream.close()
                elif fd is not None:
                    os.close(fd)
            finally:
                if handle is not None:
                    diagnostic.require(bool(api.k.CloseHandle(handle)), 'LOCK_HANDLE_CLOSE_UNCONFIRMED')


@contextmanager
def atomic_private_lock(path, api):
    """Narrow create-new or existing-private byte lock, with no ACL repair."""
    msvcrt = lock_runtime()
    @contextmanager
    def retained(stream):
        exact_lock(stream, path)
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            yield
            exact_lock(stream, path)
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    with new_private_stream(path, api) as created:
        if created is not None:
            with retained(created):
                yield True
        else:
            with api.pin(path, private=True, writable=True) as stream:
                with retained(stream):
                    yield False


def execute():
    preflight, diagnostic, refresh = modules()
    diagnostic.require(os.name == 'nt', 'WINDOWS_ROOT_ONLY')
    result = {'schema': 1, 'scope': SCOPE, 'status': 'REFUSED', 'completed': False,
        'native_eligible': False, 'private_input_allowed': False,
        'control_state_modified': False, 'pins_closed': False,
        'cli_cleanup_confirmed': False, 'image_id': diagnostic.IMAGE,
        'signature_generation': diagnostic.GENERATION,
        'preflight_source_sha256': PREFLIGHT_SHA256,
        'frozen_controller_sha256': FROZEN_CONTROLLER_SHA256,
        'program_sha256': diagnostic.PROGRAM_SHA256, 'completed_stages': []}
    # Exclusive reservation precedes every protected-input or daemon operation.
    receipt = refresh.Receipt(ROOT / RECEIPT, result)
    failure = None; payload = None; context = None; stage = None
    started = time.monotonic()

    def mark(name):
        nonlocal stage
        diagnostic.require(type(name) is str and name in (*preflight.SUCCESS_STAGES, *OWN_STAGES),
                           'CHECKPOINT_INVALID')
        if stage is not None:
            result['completed_stages'].append(stage)
        stage = name

    try:
        # checked_inputs holds the existing-only legacy lock through final close.
        with preflight.checked_inputs(mark) as context:
            mark('PREFLIGHT_PROVENANCE')
            provenance(context)
            mark('DEDICATED_LOCK')
            with atomic_private_lock(ROOT / diagnostic.STAGE / 'postcompile-diagnostic.lock', context.api):
                observation = preflight.verify_live(context, mark)
                mark('PUBLIC_PROBE')
                primary = None
                try:
                    payload = diagnostic.run_probe(ROOT, context.call, ROOT / diagnostic.PROFILE,
                                                   context.raw, observation, result)
                except BaseException as error:
                    primary = error
                # The engine is rechecked even when measurement/cleanup refused.
                if primary is not None:
                    stage = None  # Failed stages never enter completed_stages.
                mark('FINAL_ENGINE')
                diagnostic.engine(context.call)
                if primary is not None:
                    stage = 'PUBLIC_PROBE'
                    raise primary
                mark('FINAL_LIMITS')
                diagnostic.require(not context.call.uncertain
                    and shutil.disk_usage(ROOT).free >= diagnostic.FLOOR,
                    'FINAL_LIMIT_UNCONFIRMED')
                mark('DEDICATED_LOCK_CLOSE')
            mark('INPUT_CLOSE')
        result['pins_closed'] = True
        mark('FINAL_CLI')
        diagnostic.require(not context.call.uncertain, 'CLI_CLEANUP_UNCONFIRMED')
        result['cli_cleanup_confirmed'] = True
        result['completed_stages'].append('FINAL_CLI')
    except BaseException as error:
        failure = error
        # Never copy exception values, tracebacks, native output or arbitrary codes.
        result['failure_code'] = 'CONTINUATION_REFUSED'
        if stage is not None:
            result['failed_stage'] = stage
    finally:
        elapsed = time.monotonic() - started
        if not 0 <= elapsed < 600:
            failure = True
            result['failure_code'] = 'FINAL_DEADLINE'
        if failure is None:
            result.update(status='OBSERVED', completed=True, measurement=payload)
        result['total_seconds'] = round(elapsed, 3)
        try:
            receipt.save(result)
            receipt.close()
        except BaseException:
            result.update(status='REFUSED', completed=False,
                          failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            result.pop('measurement', None)
            try:
                if not receipt.stream.closed:
                    receipt.save(result)
            except BaseException:
                pass
            try:
                receipt.close()
            except BaseException:
                pass
            raise diagnostic.DiagnosticUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
    diagnostic.require(failure is None, 'CONTINUATION_REFUSED')
    return result


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    result = execute()
    print(json.dumps({'status': result['status'], 'receipt': RECEIPT,
                      'native_eligible': False}), flush=True)


if __name__ == '__main__':
    main()
