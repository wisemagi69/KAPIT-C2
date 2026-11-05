"""Offline same-host Python replay; never replaces the active application venv."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
import sysconfig
import time
import uuid
import venv

ROOT = Path(__file__).resolve().parents[1]
AREA = ROOT / '.cache/m1-runtime/reproduction'
PROVENANCE = ROOT / 'ai/reports/devops-m5-python-provenance.json'
PROVENANCE_SHA256 = 'af36445b4d7c6a747df3c4ebdf97cfed3d4391b54757759e3f7435ee882db23b'
LOCK = ROOT / 'backend/requirements-lock-cp314-win_amd64.txt'
EXPECTED = {'django': '5.2.18', 'djangorestframework': '3.18.3', 'psycopg': '3.3.6',
            'psycopg-binary': '3.3.6', 'cryptography': '50.0.2', 'pyjwt': '2.15.1',
            'asgiref': '3.12.1', 'sqlparse': '0.6.0', 'tzdata': '2026.5',
            'cffi': '2.1.1', 'pycparser': '3.11'}
OWNER = 'KAPIT-C2 offline Python replay v1'


class ReplayError(RuntimeError):
    """Fixed codes only; no subprocess output or arbitrary exception reflection."""


def fail(code):
    raise ReplayError(code)


def canonical(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def checked(path):
    path = Path(path)
    if not path.is_absolute():
        fail('PATH_REFUSED')
    try:
        parts = path.relative_to(ROOT).parts
    except ValueError:
        fail('PATH_REFUSED')
    current = ROOT
    for part in ('', *parts):
        if part in {'.', '..'}:
            fail('PATH_REFUSED')
        if part:
            current = current / part
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                fail('PATH_REFUSED')
    if path.resolve() != path:
        fail('PATH_REFUSED')
    return path


def read_fixed(path, limit, expected_hash=None):
    path = checked(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        fail('INPUT_REFUSED')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after_open = os.fstat(stream.fileno())
    after = checked(path).stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if len(raw) > limit or len({identity(s) for s in (before, opened, after_open, after)}) != 1:
        fail('INPUT_CHANGED')
    if expected_hash and hashlib.sha256(raw).hexdigest() != expected_hash:
        fail('HASH_MISMATCH')
    return raw


def manifest():
    data = json.loads(read_fixed(PROVENANCE, 65536, PROVENANCE_SHA256))
    if set(data) != {'schema', 'target', 'artifacts'} or data['schema'] != 1 or data['target'] != 'CPython 3.14 Windows AMD64':
        fail('PROVENANCE_REFUSED')
    rows = data['artifacts']
    found, bootstrap = {}, []
    if not isinstance(rows, list) or len(rows) != 12:
        fail('CLOSURE_MISMATCH')
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('name'), str):
            fail('PROVENANCE_REFUSED')
        name = canonical(row['name'])
        if row.get('role') == 'bootstrap':
            bootstrap.append(row)
        elif row.get('role') == 'application' and name not in found:
            found[name] = row['version']
        else:
            fail('CLOSURE_MISMATCH')
        if (not isinstance(row.get('filename'), str) or '/' in row['filename'] or '\\' in row['filename']
                or not re.fullmatch(r'[A-Za-z0-9_.-]+\.whl', row['filename'])
                or not re.fullmatch(r'[a-f0-9]{64}', row.get('sha256', ''))
                or type(row.get('bytes')) is not int or not 0 < row['bytes'] < 20_000_000):
            fail('PROVENANCE_REFUSED')
    if found != EXPECTED or len(bootstrap) != 1 or canonical(bootstrap[0]['name']) != 'pip' or bootstrap[0]['version'] != '26.0.1':
        fail('CLOSURE_MISMATCH')
    if len({row['filename'] for row in rows}) != 12:
        fail('CLOSURE_MISMATCH')
    return rows


def lock_bytes(rows):
    lines = ['# Target: regular CPython 3.14.4, Windows AMD64. Original publisher wheel SHA256.',
             '# Full application closure; pip bootstrap is separately verified by infra/reproduce_python.py.']
    for row in sorted((r for r in rows if r['role'] == 'application'), key=lambda r: r['name'].lower()):
        name = row['name'] + '[binary]' if row['name'] == 'psycopg' else row['name']
        lines.append(f"{name}=={row['version']} --hash=sha256:{row['sha256']}")
    return ('\n'.join(lines) + '\n').encode('ascii')


def verify_inputs(rows):
    if read_fixed(LOCK, 16384) != lock_bytes(rows):
        fail('LOCK_MISMATCH')
    house = checked(AREA / 'wheelhouse')
    if not house.is_dir() or {p.name for p in house.iterdir()} != {r['filename'] for r in rows}:
        fail('WHEELHOUSE_MISMATCH')
    for row in rows:
        raw = read_fixed(house / row['filename'], 20_000_000, row['sha256'])
        if len(raw) != row['bytes']:
            fail('ARCHIVE_SIZE_MISMATCH')


def require_target():
    if (platform.python_implementation() != 'CPython' or sys.version_info[:3] != (3, 14, 4)
            or sys.platform != 'win32' or platform.machine().upper() != 'AMD64'
            or struct.calcsize('P') != 8
            or sysconfig.get_config_var('Py_GIL_DISABLED') not in (None, 0)):
        fail('TARGET_UNAVAILABLE')


def reserve():
    parent = checked(AREA / 'runs')
    parent.mkdir(exist_ok=True)
    checked(parent)
    token = uuid.uuid4().hex
    target = checked(parent / token)
    target.mkdir()  # Exclusive: never adopt/reuse a previous target.
    marker = json.dumps({'owner': OWNER, 'run_id': token}, sort_keys=True).encode()
    with (target / 'owner.json').open('xb') as stream:
        stream.write(marker)
    return target, marker


def verify_owner(target, marker):
    if (target.parent != AREA / 'runs' or not re.fullmatch('[a-f0-9]{32}', target.name)
            or read_fixed(target / 'owner.json', 1024) != marker):
        fail('TARGET_OWNER_CHANGED')
    checked(target / 'venv')


def clean_environment(target):
    env = {name: os.environ[name] for name in ('SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT') if name in os.environ}
    for name in ('home', 'tmp'):
        checked(target / name).mkdir(exist_ok=True)
    env.update({'PATH': str(Path(sys._base_executable).parent) + os.pathsep + str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32'),
                'TEMP': str(target / 'tmp'), 'TMP': str(target / 'tmp'),
                'USERPROFILE': str(target / 'home'), 'HOME': str(target / 'home'),
                'APPDATA': str(target / 'home'), 'LOCALAPPDATA': str(target / 'home'),
                'PIP_CONFIG_FILE': os.devnull, 'PYTHONNOUSERSITE': '1',
                'VIRTUAL_ENV': str(target / 'venv'), 'PROCESSOR_ARCHITECTURE': 'AMD64'})
    return env


def child(command, env, *, capture=False):
    # All callers launch the verified isolated Python; prevent stdlib .pyc writes
    # to the shared base interpreter as well as installed-package bytecode writes.
    command = [command[0], '-B', *command[1:]]
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=180, check=False,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    except OSError:
        fail('SUBPROCESS_UNAVAILABLE')
    except subprocess.TimeoutExpired:
        fail('SUBPROCESS_TIMEOUT')
    if result.returncode != 0:
        fail('CHILD_CHECK_FAILED')
    return result.stdout if capture else None


IDENTITY = """import sys,platform,sysconfig,json,struct
print(json.dumps({'prefix':sys.prefix,'base':sys.base_prefix,'executable':sys.executable,
'version':list(sys.version_info[:3]),'implementation':platform.python_implementation(),
'platform':sys.platform,'machine':platform.machine(),'pointer_bytes':struct.calcsize('P'),'gil_disabled':sysconfig.get_config_var('Py_GIL_DISABLED')}))"""
BOOTSTRAP = """import sys,runpy
sys.path.insert(0,sys.argv.pop(1))
runpy.run_module('pip',run_name='__main__')"""
CLOSURE = """import importlib.metadata as m,json
print(json.dumps([[d.metadata['Name'],d.version] for d in m.distributions()]))"""


def verify_identity(raw, target, executable):
    data = json.loads(raw)
    if (set(data) != {'prefix', 'base', 'executable', 'version', 'implementation', 'platform', 'machine', 'pointer_bytes', 'gil_disabled'}
            or Path(data['prefix']).resolve() != (target / 'venv').resolve()
            or Path(data['base']).resolve() != Path(sys.base_prefix).resolve()
            or Path(data['executable']).resolve() != executable.resolve()
            or data['version'] != [3, 14, 4] or data['implementation'] != 'CPython'
            or data['platform'] != 'win32' or data['machine'].upper() != 'AMD64'
            or data['pointer_bytes'] != 8
            or data['gil_disabled'] not in (None, 0)):
        fail('CHILD_IDENTITY_MISMATCH')


def verify_closure(raw):
    rows = json.loads(raw)
    expected = {**EXPECTED, 'pip': '26.0.1'}
    if (not isinstance(rows, list) or len(rows) != len(expected)
            or any(not isinstance(r, list) or len(r) != 2 or not all(isinstance(x, str) for x in r) for r in rows)
            or {canonical(name): version for name, version in rows} != expected):
        fail('CLOSURE_MISMATCH')


def replay(execute=False):
    start = time.monotonic()
    phases, target = [], None
    try:
        require_target()
        rows = manifest()
        verify_inputs(rows)
        phases.append('INPUTS_VERIFIED')
        if not execute:
            return {'status': 'VERIFIED_NOT_EXECUTED', 'application': 'UNTOUCHED', 'phases': phases}
        target, marker = reserve()
        verify_owner(target, marker)
        venv.EnvBuilder(with_pip=False, symlinks=False).create(target / 'venv')
        verify_owner(target, marker)
        executable = checked(target / 'venv/Scripts/python.exe')
        env = clean_environment(target)
        verify_identity(child([str(executable), '-I', '-S', '-c', IDENTITY], env, capture=True), target, executable)
        phases.append('ISOLATED_IDENTITY_VERIFIED')
        # Private per-run locks: installation never rereads a mutable shared lock.
        app_lock = target / 'application.txt'
        app_lock.write_bytes(lock_bytes(rows))
        pip = next(row for row in rows if row['role'] == 'bootstrap')
        pip_lock = target / 'bootstrap.txt'
        pip_lock.write_text(f"pip==26.0.1 --hash=sha256:{pip['sha256']}\n", encoding='ascii')
        options = ['--isolated', '--require-virtualenv', 'install', '--no-index', '--find-links', str(AREA / 'wheelhouse'),
                   '--require-hashes', '--only-binary=:all:', '--no-cache-dir', '--no-compile',
                   '--no-input', '--disable-pip-version-check', '--keyring-provider', 'disabled']
        verify_owner(target, marker)
        verify_inputs(rows)
        child([str(executable), '-I', '-S', '-c', BOOTSTRAP, str(AREA / 'wheelhouse' / pip['filename']),
               *options, '-r', str(pip_lock)], env)
        phases.append('BOOTSTRAP_VERIFIED_INSTALLED')
        verify_owner(target, marker)
        verify_inputs(rows)
        child([str(executable), '-I', '-m', 'pip', *options, '-r', str(app_lock)], env)
        phases.append('APPLICATION_INSTALLED_OFFLINE')
        verify_owner(target, marker)
        child([str(executable), '-I', '-m', 'pip', '--isolated', '--require-virtualenv', 'check'], env)
        verify_closure(child([str(executable), '-I', '-c', CLOSURE], env, capture=True))
        verify_identity(child([str(executable), '-I', '-S', '-c', IDENTITY], env, capture=True), target, executable)
        verify_inputs(rows)
        phases.append('PIP_CHECK_EXACT_CLOSURE_VERIFIED')
        result = {'status': 'ISOLATED_OFFLINE_REPLAY_PASSED', 'application': 'UNTOUCHED',
                  'application_distributions': 11, 'bootstrap_pip': '26.0.1', 'clean_machine': 'NOT_VERIFIED'}
    except ReplayError as error:
        result = {'status': 'UNAVAILABLE', 'code': str(error), 'application': 'UNTOUCHED'}
    except Exception:
        result = {'status': 'UNAVAILABLE', 'code': 'REPLAY_UNAVAILABLE', 'application': 'UNTOUCHED'}
    result.update({'phases': phases, 'elapsed_seconds': round(time.monotonic() - start, 3),
                   'run_id': target.name if target else None, 'artifacts': 'PRESERVED_IF_CREATED'})
    if target:
        # Refuse redirected target even when recording a failure; preserve evidence.
        verify_owner(target, marker)
        (target / 'result.json').write_text(json.dumps(result, sort_keys=True), encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = replay(args.execute)
    except Exception:
        result = {'status': 'UNAVAILABLE', 'code': 'REPLAY_UNAVAILABLE', 'application': 'UNTOUCHED'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'ISOLATED_OFFLINE_REPLAY_PASSED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
