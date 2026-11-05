"""Pure profile/inspection mutation tests; no Docker, native or cache IO."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from infra import evidence_rmdir_profile as profile
from infra import evidence_native_runtime as runtime
from infra.test_evidence_native_runtime import phase, inspection


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


class RmdirProfileTests(unittest.TestCase):
    def test_import_does_not_derive_profile_or_perform_io(self):
        spec=importlib.util.spec_from_file_location('profile_inert',profile.__file__)
        module=importlib.util.module_from_spec(spec)
        with patch.object(profile.historical,'startup_profile',side_effect=AssertionError('import IO')) as derive:
            spec.loader.exec_module(module)
        derive.assert_not_called()

    def test_only_literal_rmdir_is_added_all_rules_unchanged(self):
        old=profile.historical.startup_profile();old_bytes=encoded(old)
        self.assertEqual(hashlib.sha256(old_bytes).hexdigest(),profile.OLD_PROFILE_SHA256)
        expected=deepcopy(old)
        expected['syscalls'][0]['names']=sorted(expected['syscalls'][0]['names']+['rmdir'])
        new=profile.startup_profile()
        self.assertEqual(encoded(new),encoded(expected))
        self.assertEqual(len(profile.profile_bytes()),2384)
        self.assertEqual(profile.profile_digest(),'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733')
        self.assertEqual(new['syscalls'][1:],old['syscalls'][1:])
        self.assertEqual(set(new['syscalls'][0]['names'])-set(old['syscalls'][0]['names']),{'rmdir'})
        self.assertEqual(set(old['syscalls'][0]['names'])-set(new['syscalls'][0]['names']),set())
        for forbidden in ('chmod','fchmod','fchmodat','fchmodat2'):
            self.assertFalse(any(forbidden in rule['names'] for rule in new['syscalls']))
        self.assertEqual(encoded(profile.historical.startup_profile()),old_bytes)

    def test_calls_and_nested_outputs_are_independent(self):
        first=profile.startup_profile();second=profile.startup_profile()
        self.assertIsNot(first,second)
        first['syscalls'][0]['names'].append('chmod')
        first['syscalls'][1]['args'][0]['value']=True
        self.assertEqual(profile.profile_bytes(),encoded(second))
        parsed=profile.validate_effective_profile(profile.profile_bytes())
        parsed['syscalls'][0]['names'].clear()
        self.assertEqual(profile.profile_bytes(),encoded(second))

    def test_historical_functions_and_final_helper_are_never_mutated(self):
        from backend.apps.operations import evidence_linux
        functions=(profile.historical.startup_profile,profile.historical.profile_digest,
                   profile.historical.base.seccomp_profile)
        final_syscalls=deepcopy(evidence_linux.SYSCALLS)
        final_rights=evidence_linux.SCRATCH_FS
        profile.startup_profile();profile.profile_digest()
        doc=inspection(phase());doc['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode('ascii')
        profile.normalize_inspection(doc)
        self.assertEqual(functions,(profile.historical.startup_profile,profile.historical.profile_digest,
                                    profile.historical.base.seccomp_profile))
        self.assertEqual(evidence_linux.SYSCALLS,final_syscalls)
        self.assertEqual(evidence_linux.SCRATCH_FS,final_rights)

    def test_changed_historical_source_or_shared_object_is_not_trusted(self):
        source=profile.historical.startup_profile();original=deepcopy(source)
        with patch.object(profile.historical,'startup_profile',return_value=source):
            profile.startup_profile()
            self.assertEqual(source,original)
        for change in (lambda d:d.update(defaultErrnoRet=True),lambda d:d.update(defaultAction='SCMP_ACT_ALLOW'),
                       lambda d:d['syscalls'][0]['names'].append('rmdir'),
                       lambda d:d['syscalls'][1]['args'][0].update(value=1)):
            altered=deepcopy(original);change(altered)
            with patch.object(profile.historical,'startup_profile',return_value=altered):
                with self.assertRaises(profile.ProfileUnavailable):profile.startup_profile()

    def test_canonical_and_equivalent_json_structure_are_accepted(self):
        raw=profile.profile_bytes()
        self.assertEqual(profile.validate_effective_profile(raw),profile.startup_profile())
        pretty=json.dumps(profile.startup_profile(),indent=1).encode('ascii')
        self.assertEqual(profile.validate_effective_profile(pretty),profile.startup_profile())

    def test_duplicate_keys_at_top_rule_and_argument_are_rejected(self):
        raw=profile.profile_bytes()
        changes=(raw.replace(b'"defaultErrnoRet":1',b'"defaultErrnoRet":1,"defaultErrnoRet":1'),
                 raw.replace(b'"action":"SCMP_ACT_ALLOW"',b'"action":"SCMP_ACT_ALLOW","action":"SCMP_ACT_ALLOW"',1),
                 raw.replace(b'"index":0',b'"index":0,"index":0',1))
        for changed in changes:
            self.assertNotEqual(changed,raw)
            with self.assertRaises(profile.ProfileUnavailable):profile.validate_effective_profile(changed)

    def test_profile_type_bool_numeric_schema_and_policy_mutations_refuse(self):
        changes=(lambda d:d.update(defaultErrnoRet=True),lambda d:d.update(defaultErrnoRet=1.0),
                 lambda d:d.update(defaultAction='SCMP_ACT_ALLOW'),lambda d:d.update(defaultErrnoRet=0),
                 lambda d:d.update(architectures=['SCMP_ARCH_AARCH64']),lambda d:d.update(schema=1),
                 lambda d:d['syscalls'][0]['names'].append('chmod'),lambda d:d['syscalls'][0]['names'].remove('rmdir'),
                 lambda d:d['syscalls'][0]['names'].append('rmdir'),lambda d:d['syscalls'][0]['names'].reverse(),
                 lambda d:d['syscalls'][1]['args'][0].update(value=False),
                 lambda d:d['syscalls'][1]['args'][0].update(op='SCMP_CMP_NE'),
                 lambda d:d['syscalls'].append(deepcopy(d['syscalls'][-1])))
        for change in changes:
            doc=profile.startup_profile();change(doc)
            with self.subTest(changed=repr(change)),self.assertRaises(profile.ProfileUnavailable):
                profile.validate_effective_profile(encoded(doc))

    def test_malformed_nonfinite_paths_unconfined_bounds_and_primitive_types_refuse(self):
        for raw in (b'',b'unconfined',b'/tmp/profile.json',b'"unconfined"',b'{"x":NaN}',b'{"x":Infinity}',
                    b'null',b'false',b'[]',b'{}',b'x'*16385,b'['*100+b']'*100,b'\xff',
                    profile.profile_bytes().decode('ascii'),bytearray(profile.profile_bytes()),None):
            with self.subTest(kind=type(raw).__name__),self.assertRaises(profile.ProfileUnavailable):
                profile.validate_effective_profile(raw)

    def test_normalization_changes_only_one_effective_field_and_never_input(self):
        for reversed_options in (False,True):
            document=inspection(phase())
            options=['no-new-privileges=true','seccomp='+profile.profile_bytes().decode('ascii')]
            if reversed_options:options.reverse()
            document['HostConfig']['SecurityOpt']=options
            original=deepcopy(document)
            normalized=profile.normalize_inspection(document)
            self.assertEqual(document,original)
            expected=deepcopy(document)
            index=0 if reversed_options else 1
            expected['HostConfig']['SecurityOpt'][index]='seccomp='+encoded(profile.historical.startup_profile()).decode('ascii')
            self.assertEqual(normalized,expected)
            self.assertIsNot(normalized,document)
            normalized['Config']['Labels'].clear()
            self.assertEqual(document,original)

    def test_new_profile_validation_precedes_inspection_copy(self):
        document={'HostConfig':{'SecurityOpt':['no-new-privileges=true','seccomp=unconfined']}}
        with patch.object(profile,'deepcopy',wraps=deepcopy) as copying:
            with self.assertRaises(profile.ProfileUnavailable):profile.normalize_inspection(document)
        self.assertFalse(any(call.args and call.args[0] is document for call in copying.call_args_list))

    def test_inspection_wrong_options_paths_extra_types_and_old_profile_refuse(self):
        good='seccomp='+profile.profile_bytes().decode('ascii')
        for options in (None,[],['no-new-privileges=true'],['no-new-privileges=true',good,good],
                        ['no-new-privileges=true','no-new-privileges=true'],[good,good],
                        ['no-new-privileges=false',good],['no-new-privileges=true',True],
                        ['no-new-privileges=true','seccomp=/fixed/profile.json'],
                        ['no-new-privileges=true','seccomp=unconfined'],
                        ['no-new-privileges=true','seccomp='+encoded(profile.historical.startup_profile()).decode('ascii')],
                        ('no-new-privileges=true',good)):
            doc={'HostConfig':{'SecurityOpt':options}}
            with self.subTest(options_type=type(options).__name__),self.assertRaises(profile.ProfileUnavailable):
                profile.normalize_inspection(doc)
        for doc in (None,[],{}, {'HostConfig':[]},{'HostConfig':True}):
            with self.assertRaises(profile.ProfileUnavailable):profile.normalize_inspection(doc)

    def test_unchanged_full_inspection_validator_still_accepts_normalized_modes(self):
        for mode in ('scan','decode'):
            for running in (False,True):
                p=phase(mode);doc=inspection(p,running=running)
                doc['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode('ascii')
                with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(doc,p,container_id='e'*64,running=running)
                normalized=profile.normalize_inspection(doc)
                runtime.verify_inspection(normalized,p,container_id='e'*64,running=running)

    def test_normalization_does_not_sanitize_other_unsafe_container_fields(self):
        changes=(lambda d:d['HostConfig'].update(Memory=True),lambda d:d['HostConfig'].update(Privileged=True),
                 lambda d:d['HostConfig'].update(NetworkMode='host'),lambda d:d['Config'].update(User='0:0'),
                 lambda d:d['Config']['Labels'].update(unexpected='canary'),lambda d:d.update(Image='sha256:'+'f'*64))
        for change in changes:
            p=phase();doc=inspection(p);doc['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode('ascii')
            change(doc)
            normalized=profile.normalize_inspection(doc)
            with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(normalized,p,container_id='e'*64)


if __name__ == '__main__':unittest.main()
