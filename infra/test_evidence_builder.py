"""Public resolver policy/lifecycle doubles; no Docker/APT/native invocation."""
from contextlib import contextmanager
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from infra import evidence_builder as b

CID = 'c'*64
ENV = ['PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'RUST_VERSION=1.88.0']


def apt_output():
    rows = ['Inst '+name+' ('+version+' Debian:12.11/oldstable [amd64])' for name, version in b.REQUESTED.items()]
    rows += ['Inst cmake-data (3.25.1-1 Debian:12.11/oldstable [all])',
             'KAPIT_BASE_STATUS_SHA256 '+'a'*64, 'KAPIT_BASE_INVENTORY_SHA256 '+'d'*64]
    return ('\n'.join(rows)+'\n').encode()


def image():
    return {'Id': b.IMAGE_ID, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [b.IMAGE],
            'Config': {'Env': ENV, 'Labels': {'org.opencontainers.image.source': b.OCI_SOURCE},
                       'Volumes': None, 'Healthcheck': None}}


def inspection(policy):
    return {'Id': CID, 'Name': '/'+policy.name, 'Image': b.IMAGE_ID, 'Mounts': [],
            'Config': {'Labels': policy.labels, 'Env': ENV, 'Entrypoint': ['/usr/bin/env'], 'Cmd': b.command(),
                       'User': '0:0', 'WorkingDir': '/tmp', 'OpenStdin': False, 'Tty': False, 'Volumes': None,
                       'Healthcheck': {'Test': ['NONE']}},
            'HostConfig': {'ReadonlyRootfs': False, 'NetworkMode': 'none', 'IpcMode': 'none', 'PidMode': '',
                'CgroupnsMode': 'private', 'Privileged': False, 'Memory': b.MEMORY, 'MemorySwap': b.MEMORY,
                'NanoCpus': 1000000000, 'PidsLimit': 16, 'CapDrop': ['ALL'], 'CapAdd': None,
                'SecurityOpt': ['no-new-privileges=true'], 'LogConfig': {'Type': 'none', 'Config': {}},
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                'Ulimits': [{'Name': 'cpu', 'Soft': 120, 'Hard': 120}, {'Name': 'nofile', 'Soft': 128, 'Hard': 128},
                            {'Name': 'core', 'Soft': 0, 'Hard': 0}]},
            'State': {'Running': False, 'Paused': False, 'Restarting': False, 'Pid': 0, 'ExitCode': 0, 'OOMKilled': False, 'Status': 'created'}}


class HostDouble:
    def __init__(self, policy):
        self.policy = policy; self.events = []; self.saved = {}; self.create_output = CID.encode()+b'\n'
        self.ambiguous_exists = False; self.removal_failure = False; self.interrupt = False
        self.persistence_failure = False; self.changed_owner = False; self.created = False; self.started = False
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def save(self, name, value):
        self.events.append(('save', name))
        if self.persistence_failure: raise OSError('synthetic storage error')
        self.saved[name] = value
    def call(self, *args, timeout=15):
        self.events.append(args)
        if args[:2] == ('image', 'inspect'): return 0, json.dumps([image()]).encode(), b'', 'EXIT'
        if args[:2] == ('container', 'ls'):
            output = (CID+'\n').encode() if self.created and self.ambiguous_exists and any('name=' in arg for arg in args) else b''
            return 0, output, b'', 'EXIT'
        if args[:2] == ('container', 'create'):
            self.created = True; return 0, self.create_output, b'', 'EXIT'
        if args[:2] == ('container', 'inspect'):
            self.assert_exact_id(args)
            value = inspection(self.policy)
            if self.started: value['State']['Status'] = 'exited'
            if self.changed_owner: value['Name'] = '/unrelated'
            return 0, json.dumps([value]).encode(), b'', 'EXIT'
        if args[:2] == ('container', 'cp'):
            if 'ownership.json' not in self.saved: raise AssertionError('copy before ownership persisted')
            return 0, b'', b'', 'EXIT'
        if args[:2] == ('container', 'start'):
            self.assert_exact_id(args)
            self.started = True
            if self.interrupt: raise KeyboardInterrupt()
            return 0, apt_output(), b'', 'EXIT'
        if args[:2] in [('container', 'rm'), ('container', 'kill')]:
            self.assert_exact_id(args)
            return (1 if self.removal_failure else 0), b'', b'', 'EXIT'
        raise AssertionError('unexpected native operation')
    def assert_exact_id(self, args):
        if args[-1] != CID: raise AssertionError('name or unknown ID adoption')


class ResolverPolicyTests(unittest.TestCase):
    def test_default_and_invalid_optin_do_not_construct_host(self):
        with patch.object(b, '_Host', side_effect=AssertionError('host access')):
            self.assertEqual(b.run(), b.preparation())
            for options in [{'execute': 1}, {'execute': True, 'reservation': '../bad'}, {'execute': True, 'reservation': None}]:
                with self.assertRaises(b.BuilderUnavailable): b.run(**options)

    def test_actual_image_alias_platform_and_inherited_labels_are_bound(self):
        self.assertEqual(b.verify_image(image()), ENV)
        for field, value in [('Id', 'sha256:'+'0'*64), ('Architecture', 'arm64'), ('Os', 'windows'), ('RepoDigests', ['attacker.invalid/rust@'+b.IMAGE_ID])]:
            changed = image(); changed[field] = value
            with self.assertRaises(b.BuilderUnavailable): b.verify_image(changed)
        for field, value in [('Labels', {}), ('Volumes', {'/data': {}}), ('Healthcheck', {'Test': ['CMD', 'arbitrary']}), ('Env', ['X=1', 'X=2'])]:
            changed = image(); changed['Config'][field] = value
            with self.assertRaises(b.BuilderUnavailable): b.verify_image(changed)

    def test_whole_created_configuration_no_mount_network_or_privilege_substitution(self):
        policy = b.ResolverPolicy('a'*32); value = inspection(policy)
        b.verify_inspection(value, policy, CID, ENV)
        exited = copy.deepcopy(value); exited['State']['Status'] = 'exited'
        b.verify_inspection(exited, policy, CID, ENV, after=True)
        for field, changed_value in [('Memory', True), ('MemorySwap', -1), ('PidsLimit', 0), ('ReadonlyRootfs', True),
                                     ('NetworkMode', 'host'), ('PidMode', 'host'), ('Binds', ['/workspace:/host']),
                                     ('CapAdd', ['SYS_ADMIN']), ('SecurityOpt', ['seccomp=unconfined'])]:
            changed = copy.deepcopy(value); changed['HostConfig'][field] = changed_value
            with self.subTest(field=field), self.assertRaises(b.BuilderUnavailable): b.verify_inspection(changed, policy, CID, ENV)
        for field, changed_value in [('Labels', {'org.kapit.owner': b.OWNER}), ('Cmd', ['apt-get', 'install', 'arbitrary']),
                                     ('Env', ENV+['APT_CONFIG=/host']), ('Entrypoint', ['/bin/bash'])]:
            changed = copy.deepcopy(value); changed['Config'][field] = changed_value
            with self.assertRaises(b.BuilderUnavailable): b.verify_inspection(changed, policy, CID, ENV)

    def test_script_is_file_only_signed_snapshot_simulation_with_isolated_config(self):
        value = b.script()
        self.assertIn('file:/tmp/kapit-repo bookworm main', value)
        self.assertIn('signed-by=/usr/share/keyrings/debian-archive-keyring.gpg', value)
        self.assertIn('Dir::Etc::parts "/tmp/kapit-apt/empty"', value)
        self.assertIn('Acquire::Check-Valid-Until "false"', value)
        self.assertIn('APT::Get::AllowUnauthenticated "false"', value)
        self.assertNotIn('trusted=yes', value); self.assertNotIn('https://', value)
        self.assertEqual(value.count('apt-get --simulate'), 1)
        self.assertNotIn('apt-get install', value)
        self.assertIn('KAPIT_STATUS_BEFORE', value); self.assertIn('KAPIT_INVENTORY_BEFORE', value)
        self.assertEqual(b.command()[:2], ['-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin'])

    def test_parser_outputs_only_closed_inst_records_and_baseline_hashes(self):
        result = b.parse_resolution(b'public apt informational line\n'+apt_output())
        self.assertEqual(set(result), {'packages', 'baseline_status_sha256', 'baseline_inventory_sha256'})
        self.assertEqual(len(result['packages']), 4)
        self.assertTrue(all(set(row) == {'package', 'version', 'architecture'} for row in result['packages']))
        self.assertEqual(result['baseline_status_sha256'], 'a'*64)

    def test_parser_rejects_ambiguity_removals_wrong_versions_arch_unknown_and_missing_hashes(self):
        raw = apt_output()
        for changed in [raw.replace(b'cmake (3.25.1-1', b'cmake (3.25.0-1'), raw.replace(b'[amd64]', b'[arm64]', 1),
                        raw+b'Remv unrelated [1]\n', raw+b'Inst broken\n', raw+b'Inst cmake (3.25.1-1 Debian [all])\n',
                        raw.replace(b'KAPIT_BASE_STATUS_SHA256', b'UNKNOWN'), raw+b'KAPIT_BASE_STATUS_SHA256 '+'f'.encode()*64+b'\n',
                        b'\xff', b'x'*1048577]:
            with self.assertRaises(b.BuilderUnavailable): b.parse_resolution(changed)


class ResolverLifecycleTests(unittest.TestCase):
    def setUp(self): self.policy = b.ResolverPolicy('a'*32)

    def test_original_id_durable_before_inspect_copy_start_exact_two_public_files(self):
        host = HostDouble(self.policy); result = b._execute(self.policy, host)
        save_index = host.events.index(('save', 'ownership.json'))
        inspect_index = host.events.index(('container', 'inspect', CID))
        self.assertLess(save_index, inspect_index)
        copied = [event for event in host.events if event[:2] == ('container', 'cp')]
        self.assertEqual(copied, [('container', 'cp', str(b.STAGE/name), CID+':'+target) for name, (_, _, target) in b.INPUTS.items()])
        self.assertEqual(host.saved['ownership.json']['created_id'], CID)
        self.assertEqual(result['cleanup'], 'OWNED_CONTAINER_ABSENT_VERIFIED')
        self.assertFalse(result['runtime_approval']); self.assertFalse(result['private_input_allowed'])
        self.assertEqual(result['dependency_closure'], 'RESOLUTION_ONLY_NOT_ACQUIRED_OR_INSTALLED')

    def test_persistence_failure_cleans_original_id_without_starting(self):
        host = HostDouble(self.policy); host.persistence_failure = True
        with self.assertRaises(OSError): b._execute(self.policy, host)
        self.assertIn(('container', 'rm', CID), host.events)
        self.assertFalse(any(event[:2] in [('container', 'cp'), ('container', 'start')] for event in host.events))

    def test_unknown_id_absent_never_adopted_or_inspected(self):
        host = HostDouble(self.policy); host.create_output = b'lost id'
        with self.assertRaises(b.BuilderUnavailable): b._execute(self.policy, host)
        self.assertFalse(any(event[:2] in [('container', 'inspect'), ('container', 'rm'), ('container', 'kill')] for event in host.events))
        self.assertNotIn('ownership.json', host.saved)

    def test_unknown_id_existing_name_preserved_cleanup_unconfirmed(self):
        host = HostDouble(self.policy); host.create_output = b'lost id'; host.ambiguous_exists = True
        with self.assertRaises(b.BuilderUnavailable) as error: b._execute(self.policy, host)
        self.assertEqual(error.exception.code, 'BUILDER_CLEANUP_UNCONFIRMED')
        self.assertIsNone(error.exception.container_id)
        self.assertFalse(any(event[:2] in [('container', 'inspect'), ('container', 'rm'), ('container', 'kill')] for event in host.events))

    def test_interruption_cleans_and_propagates_but_uncertainty_dominates(self):
        host = HostDouble(self.policy); host.interrupt = True
        with self.assertRaises(KeyboardInterrupt): b._execute(self.policy, host)
        self.assertIn(('container', 'rm', CID), host.events)
        self.assertNotIn('result.json', host.saved)
        host = HostDouble(self.policy); host.interrupt = True; host.removal_failure = True
        with self.assertRaises(b.BuilderUnavailable) as error: b._execute(self.policy, host)
        self.assertEqual(error.exception.code, 'BUILDER_CLEANUP_UNCONFIRMED')
        self.assertEqual(error.exception.container_id, CID)

    def test_changed_identity_never_killed_or_removed(self):
        host = HostDouble(self.policy); host.changed_owner = True
        with self.assertRaises(b.BuilderUnavailable) as error: b._execute(self.policy, host)
        self.assertEqual(error.exception.code, 'BUILDER_CLEANUP_UNCONFIRMED')
        self.assertFalse(any(event[:2] in [('container', 'rm'), ('container', 'kill')] for event in host.events))

    def test_public_run_suppresses_raw_failure_detail(self):
        with patch.object(b, '_Host', side_effect=OSError('synthetic private detail')):
            with self.assertRaises(b.BuilderUnavailable) as error: b.run(execute=True, reservation='a'*32)
        self.assertEqual(str(error.exception), 'BUILDER_RESOLUTION_UNAVAILABLE')

    def test_durable_receipt_protects_then_writes_flushes_fsyncs_and_pins_before_return(self):
        events, written = [], bytearray()
        class File:
            def __enter__(self): return self
            def __exit__(self, *_): events.append('close')
            def write(self, raw): events.append('write'); written.extend(raw); return len(raw)
            def flush(self): events.append('flush')
            def fileno(self): return 42
        class Api:
            def protect(self, path): events.append('protect')
            @contextmanager
            def pin(self, path, **options):
                events.append('pin')
                yield io.BytesIO(bytes(written))
        host = b._Host(self.policy); host.stage = Path('synthetic-owned-stage'); host.api = Api()
        doc = {'schema': 1, 'created_id': CID}
        with patch.object(Path, 'open', side_effect=lambda *_, **__: File()), \
             patch.object(b.os, 'fsync', side_effect=lambda _: events.append('fsync')):
            host.save('ownership.json', doc)
        self.assertLess(events.index('protect'), events.index('write'))
        self.assertLess(events.index('write'), events.index('flush'))
        self.assertLess(events.index('flush'), events.index('fsync'))
        self.assertLess(events.index('fsync'), events.index('pin'))
        self.assertEqual(json.loads(written), doc)
        host.stack.close()


if __name__ == '__main__': unittest.main()
