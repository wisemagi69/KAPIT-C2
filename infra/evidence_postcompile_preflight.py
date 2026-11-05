"""Fixed read-only public scanner preflight. Import is inert; no CLI options."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import time

ROOT = Path(__file__).resolve().parents[1]
FROZEN_CONTROLLER = 'infra/evidence_postcompile_diagnostic.py'
FROZEN_CONTROLLER_SHA256 = '5a24dbfa6de043730faa10c9ec3a8ba46fff8446d44fa82401977698dfda69ff'
PREFLIGHT_RECEIPT = 'ai/state/private-scanner-continuation-preflight-pcre.json'
SCOPE = 'PUBLIC_POSTCOMPILE_CONTINUATION_PREFLIGHT_ONLY'
SUCCESS_STAGES = ('ROOT_PINS', 'SOURCE_PINS', 'PROFILE_PIN', 'PRESERVED_REFUSALS',
    'CLIENT_PINS', 'LEGACY_LOCK', 'ORIGINAL_BINDING', 'PRIOR_RESERVATIONS',
    'FRESH_IMAGE', 'CGROUP_V2', 'DISK_FLOOR', 'DIAGNOSTIC_OWNER_ABSENCE',
    'ORIGINAL_LIVE_POSTFLIGHT', 'FINAL_LIVE_LIMITS')
REFUSALS = (
    ('ai/state/private-scanner-postcompile-diagnostic-pcre.json',
     '3a806b13312656a8436bb1efad91f600ffe14cf53032e2a0255e4a05428dc9b5', 0.022),
    ('ai/state/private-scanner-postcompile-diagnostic-v2-pcre.json',
     'd5ef1493ce963407b4283c6fb9529d1b702f2b01fb3240b2e485439b1995d818', 0.013))


def modules():
    from infra import evidence_postcompile_diagnostic as old
    return old, *old.modules()


@dataclass(frozen=True)
class Context:
    api: object
    pins: object
    call: object
    raw: bytes


class ReadonlyQueries:
    """Fixed query vocabulary; mutations cannot reach the retained CLI boundary."""
    def __init__(self, call):
        self._call = call

    @property
    def count(self): return self._call.count

    @property
    def uncertain(self): return self._call.uncertain

    def __call__(self, *args, timeout=15):
        old, *_ = modules()
        allowed = (
            ('info', '--format', '{{.ID}}'),
            ('info', '--format', '{{.CgroupVersion}}'),
            ('container', 'inspect', old.OLD_CID),
            ('container', 'inspect', old.OLD_NAME),
            ('container', 'ls', '--all', '--no-trunc', '--filter',
             'label=org.kapit.owner=' + old.OWNER, '--format', '{{.ID}}'))
        old.require(args in allowed and type(timeout) is int and timeout == 15,
            'READ_ONLY_QUERY_REFUSED')
        try:
            value = self._call(*args, timeout=15)
            old.require(type(value) is tuple and len(value) == 4)
            code, out, err, reason = value
            old.require(type(code) is int and type(out) is bytes and type(err) is bytes
                and len(out) <= 65536 and len(err) <= 65536 and reason == 'EXIT'
                and (args[:2] == ('container', 'inspect') or err == b'')
                and not self._call.uncertain, 'READ_ONLY_QUERY_UNCONFIRMED')
            return value
        except BaseException:
            self._call.uncertain = True
            raise


def preserved_refusals(pins, api):
    old, refresh, *_ = modules()
    for name, expected, duration in REFUSALS:
        raw = refresh.pin_bytes(ROOT, pins, api, name, expected=expected, maximum=8192)
        old.require(len(raw) == 503, 'PRIOR_REFUSAL_CHANGED')
        expected_value = {'schema': 1, 'scope': 'PUBLIC_POSTCOMPILE_CONTROLLER_DIAGNOSTIC_ONLY',
            'status': 'REFUSED', 'completed': False, 'control_state_modified': False,
            'native_eligible': False, 'pins_closed': True, 'private_input_allowed': False,
            'image_id': old.IMAGE, 'signature_generation': old.GENERATION,
            'failure_code': 'POSTCOMPILE_DIAGNOSTIC_REFUSED', 'total_seconds': duration}
        # Canonical equality also rejects bool/int substitution that dict equality allows.
        value = refresh.document(raw)
        old.require(json.dumps(value, sort_keys=True, allow_nan=False) ==
            json.dumps(expected_value, sort_keys=True, allow_nan=False), 'PRIOR_REFUSAL_CHANGED')


@contextmanager
def checked_inputs(mark):
    """Hold exact inherited input contracts and the existing launcher lock."""
    old, refresh, *_ = modules()
    from infra.evidence_tools import Windows
    from infra.live_recovery_drill import PrivateDirectory
    old.require(os.name == 'nt', 'WINDOWS_ROOT_ONLY')
    pins = ExitStack()
    try:
        api = Windows()
        mark('ROOT_PINS')
        path = ROOT
        pins.enter_context(api.pin(path, directory=True))
        for part in Path(old.STAGE).parts:
            path /= part
            pins.enter_context(api.pin(path, directory=True))
        pins.enter_context(PrivateDirectory().pin(ROOT / old.STAGE, private=True, directory=True))
        mark('SOURCE_PINS')
        refresh.pin_bytes(ROOT, pins, api, FROZEN_CONTROLLER, expected=FROZEN_CONTROLLER_SHA256)
        for name, expected in old.SOURCE_PINS.items():
            refresh.pin_bytes(ROOT, pins, api, name, expected=expected)
        raw = refresh.pin_bytes(ROOT, pins, api, old.PROGRAM, expected=old.PROGRAM_SHA256)
        mark('PROFILE_PIN')
        old.profile_source(ROOT, pins, api)
        mark('PRESERVED_REFUSALS')
        preserved_refusals(pins, api)
        mark('CLIENT_PINS')
        docker, _, config, _ = refresh.tools(ROOT, pins, api)
        call = old.Commands(docker, config)
        mark('LEGACY_LOCK')
        pins.enter_context(old.legacy_lock(api))
        mark('ORIGINAL_BINDING')
        old.original_documents(ROOT, pins, api)
        mark('PRIOR_RESERVATIONS')
        old.unknown_diagnostics(ROOT, pins, api)
        yield Context(api, pins, call, raw)
    finally:
        try:
            pins.close()
        except BaseException:
            raise old.DiagnosticUnavailable('INPUT_CLOSE_UNCONFIRMED') from None


def diagnostic_owner_absent(call):
    """Specific unknown-owner guard, never a global-idle assertion."""
    old, *_ = modules()
    code, out, err, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
        'label=org.kapit.owner=' + old.OWNER, '--format', '{{.ID}}')
    old.require(type(code) is int and code == 0 and reason == 'EXIT'
        and out in (b'', b'\n', b'\r\n') and err == b'', 'PRIOR_DIAGNOSTIC_UNCONFIRMED')


def verify_live(context, mark):
    """Every call repeats actual UTC/package/image and original ownership proof."""
    old, refresh, runtime, *_ = modules()
    old.require(type(context) is Context)
    query = ReadonlyQueries(context.call)
    mark('FRESH_IMAGE')
    saved = refresh.verified_image(ROOT, context.pins, context.api)
    old.require(saved.get('image_id') == old.IMAGE and saved.get('signature_generation') == old.GENERATION)
    mark('CGROUP_V2')
    runtime._require_cgroup_v2(query)
    mark('DISK_FLOOR')
    old.require(shutil.disk_usage(ROOT).free >= old.FLOOR, 'LOW_SPACE')
    mark('DIAGNOSTIC_OWNER_ABSENCE')
    diagnostic_owner_absent(query)
    mark('ORIGINAL_LIVE_POSTFLIGHT')
    observation = old.observe_original(query)
    mark('FINAL_LIVE_LIMITS')
    old.require(not context.call.uncertain and shutil.disk_usage(ROOT).free >= old.FLOOR,
        'FINAL_LIVE_UNCONFIRMED')
    return observation


def validate_receipt(value, expected_source_sha256):
    """Pure closed-schema provenance check. It never grants live clearance."""
    old, *_ = modules()
    old.require(type(value) is dict and type(expected_source_sha256) is str
        and re.fullmatch('[0-9a-f]{64}', expected_source_sha256) is not None)
    fixed = {'schema': 1, 'scope': SCOPE, 'status': 'PREFLIGHT_COMPLETE',
        'completed': True, 'read_only': True, 'container_actions': False,
        'native_eligible': False, 'private_input_allowed': False, 'control_state_modified': False,
        'pins_closed': True, 'cli_cleanup_confirmed': True,
        'source_sha256': expected_source_sha256, 'frozen_controller_sha256': FROZEN_CONTROLLER_SHA256,
        'program_sha256': old.PROGRAM_SHA256, 'image_id': old.IMAGE,
        'signature_generation': old.GENERATION, 'completed_stages': list(SUCCESS_STAGES)}
    old.require(set(value) == set(fixed) | {'total_seconds'})
    old.require(all(type(value[key]) is type(expected) and value[key] == expected
        for key, expected in fixed.items()))
    seconds = value['total_seconds']
    old.require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 <= seconds < 600)


def execute():
    old, refresh, *_ = modules()
    old.require(os.name == 'nt', 'WINDOWS_ROOT_ONLY')
    started = time.monotonic()
    result = {'schema': 1, 'scope': SCOPE, 'status': 'REFUSED', 'completed': False,
        'read_only': True, 'container_actions': False, 'native_eligible': False,
        'private_input_allowed': False, 'control_state_modified': False, 'pins_closed': False,
        'cli_cleanup_confirmed': False,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'frozen_controller_sha256': FROZEN_CONTROLLER_SHA256, 'program_sha256': old.PROGRAM_SHA256,
        'image_id': old.IMAGE, 'signature_generation': old.GENERATION, 'completed_stages': []}
    receipt = refresh.Receipt(ROOT / PREFLIGHT_RECEIPT, result)
    active = None; failure = None; context = None
    def mark(stage):
        nonlocal active
        old.require(stage in SUCCESS_STAGES)
        index = len(result['completed_stages'])
        if active is not None:
            result['completed_stages'].append(active)
            index += 1
        old.require(index < len(SUCCESS_STAGES) and SUCCESS_STAGES[index] == stage)
        active = stage
    try:
        with checked_inputs(mark) as context:
            verify_live(context, mark)  # Discard; a receipt is never clearance.
            old.require(not context.call.uncertain)
        result['pins_closed'] = True
        result['cli_cleanup_confirmed'] = not context.call.uncertain
        result['completed_stages'].append(active)
        old.require(result['completed_stages'] == list(SUCCESS_STAGES))
        old.require(time.monotonic() - started < 600, 'FINAL_DEADLINE')
    except BaseException as error:
        failure = error
        result['failure_code'] = 'PREFLIGHT_REFUSED'
        if active in SUCCESS_STAGES: result['failed_stage'] = active
        if type(error) is old.DiagnosticUnavailable and error.code == 'INPUT_CLOSE_UNCONFIRMED':
            result['failure_code'] = 'INPUT_CLOSE_UNCONFIRMED'
            result['failed_stage'] = 'INPUT_CLOSE'
        elif context is not None:
            # Normal context exit, including failures, closes all retained pins.
            result['pins_closed'] = True
        result['cli_cleanup_confirmed'] = context is not None and not context.call.uncertain
    if failure is None:
        result.update(status='PREFLIGHT_COMPLETE', completed=True)
    result['total_seconds'] = round(time.monotonic() - started, 3)
    try:
        receipt.save(result)
        receipt.close()
    except BaseException:
        result.update(status='REFUSED', completed=False, failure_code='RECEIPT_CLOSE_UNCONFIRMED')
        try:
            if not receipt.stream.closed: receipt.save(result)
        except BaseException: pass
        try: receipt.close()
        except BaseException: pass
        raise old.DiagnosticUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
    old.require(failure is None)
    return result


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    result = execute()
    print(json.dumps({'status': result['status'], 'receipt': PREFLIGHT_RECEIPT,
        'native_eligible': False}), flush=True)


if __name__ == '__main__':
    main()
