"""Small semantic byte fixtures, not positive full official-runtime evidence."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tarfile
from types import MappingProxyType
import unittest
from unittest.mock import patch
import zipfile

from infra import evidence_native_package as package
from infra.test_evidence_elf import image

RUNTIME_RECIPE=Path('infra/native/Dockerfile.evidence-runtime').read_bytes()


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',',':')).encode()


def fixture():
    library=image(soname='libclamav.so.12',needed=('libdemo.so.1',))
    dependency=image(soname='libdemo.so.1')
    row=lambda path,origin,data,soname: {'path':path,'origin':origin,'sha256':package.build.sha256(data),'size':len(data),'soname':soname}
    records=[row('/builder/libdemo.so.1','builder',dependency,'libdemo.so.1'),
             row(package.LIBRARY_PATH,'root',library,'libclamav.so.12')]
    doc={'schema':1,'scope':'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF',
         'compiler_image':package.COMPILER_IMAGE,'runtime_base':package.RUNTIME_BASE,'inventory':records,
         'edges':[[package.LIBRARY_PATH,'libdemo.so.1','/builder/libdemo.so.1']], 'cycles':[],
         'export_receipts':['ai/state/private-scanner-export-'+'a'*32+'.json','ai/state/private-scanner-export-'+'b'*32+'.json'],
         'native_executed':False,'native_eligible':False}
    return doc,library,dependency


def archive(files, *, kinds=None):
    sink=io.BytesIO()
    with tarfile.open(fileobj=sink,mode='w',format=tarfile.USTAR_FORMAT) as output:
        for name,data in files:
            item=tarfile.TarInfo(name); item.size=len(data); item.type=(kinds or {}).get(name,tarfile.REGTYPE)
            output.addfile(item,io.BytesIO(data))
    return sink.getvalue()


def packed(doc,dependency, extras=()):
    return archive([('inventory.json',encoded(doc)),('lib/libdemo.so.1',dependency),*extras])


class NativePackageTests(unittest.TestCase):
    def test_exact_corrected_compiler_identity_accepts_only_matching_closure(self):
        corrected = 'sha256:b712bfbd9e15a3e0a973b3a6d9ca3574caa3c4c9cdfb3742b04c2bbd136f08d3'
        self.assertEqual(package.COMPILER_IMAGE, corrected)
        doc, library, dependency = fixture()
        self.assertEqual(doc['compiler_image'], corrected)
        accepted = package.closure_context(packed(doc, dependency), library)
        self.assertEqual(accepted['closure/lib/libdemo.so.1'], dependency)
        # Identical actual-byte fixture and graph, changing only provenance.
        # The former compiled image does not acquire the getter/readback repair.
        for identity in [
            'sha256:3635be44be35fc4b3ad0312b136d87ffbcdac2b5f11d83a4c3160451722aed6c',
            'sha256:d6dd010cf0596c818ed92c9530b35f5be1105c501d432be4509e0b78d7fc99f2',
            'sha256:'+'f'*64, corrected.upper(), 'kapit-public-strict-build:latest',
            corrected+' ', None, True, 0, {'verified': corrected},
        ]:
            changed = deepcopy(doc)
            changed['compiler_image'] = identity
            with self.subTest(identity_type=type(identity).__name__), self.assertRaises(package.PackageUnavailable):
                package.closure_context(packed(changed, dependency), library)

    def test_small_metadata_graph_binds_actual_bytes_without_elf_claim(self):
        doc,library,dependency=fixture()
        context=package.closure_context(packed(doc,dependency),library)
        self.assertEqual(set(context),{'closure/inventory.json','closure/lib/libdemo.so.1'})
        self.assertEqual(context['closure/lib/libdemo.so.1'],dependency)

    def test_closed_inventory_no_caller_trust_flags_or_wrong_images(self):
        doc,library,dependency=fixture()
        changes=[('schema',True),('compiler_image','sha256:'+'f'*64),('runtime_base','sha256:'+'a'*64),
                 ('native_executed',True),('native_eligible',True),('verified',True),('scope','READY')]
        for key,value in changes:
            changed=deepcopy(doc);changed[key]=value
            with self.subTest(key=key),self.assertRaises(package.PackageUnavailable):
                package.closure_context(packed(changed,dependency),library)

    def test_library_and_builder_hash_size_and_exact_member_set(self):
        doc,library,dependency=fixture()
        for raw,compiled in [(packed(doc,dependency+b'x'),library),(packed(doc,dependency),library+b'x'),
                             (packed(doc,dependency,[('lib/extra.so',b'x')]),library),
                             (archive([('inventory.json',encoded(doc))]),library)]:
            with self.assertRaises(package.PackageUnavailable):package.closure_context(raw,compiled)
        for key,value in [('size',True),('sha256','0'*64),('soname','../bad.so'),('origin','verified')]:
            changed=deepcopy(doc);changed['inventory'][0][key]=value
            with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)

    def test_paths_protected_overrides_duplicate_providers_and_unreachable_records(self):
        doc,library,dependency=fixture()
        for path in ['/builder/../libdemo.so.1','/builder/tree/libdemo.so.1','/etc/libdemo.so.1','//builder/libdemo.so.1']:
            changed=deepcopy(doc);changed['inventory'][0]['path']=path
            with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)
        changed=deepcopy(doc);changed['inventory'][0]['soname']='libc.so.6'
        with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)
        changed=deepcopy(doc);changed['inventory'][0]['soname']='libclamav.so.12'
        with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)
        changed=deepcopy(doc);changed['edges']=[]
        with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)

    def test_edges_and_cycles_require_known_unique_actual_edge_paths(self):
        doc,library,dependency=fixture()
        for edges in [[['/unknown','libdemo.so.1','/builder/libdemo.so.1']],
                      [[package.LIBRARY_PATH,'wrong.so','/builder/libdemo.so.1']],doc['edges']*2]:
            changed=deepcopy(doc);changed['edges']=edges
            with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)
        changed=deepcopy(doc)
        changed['edges'].append(['/builder/libdemo.so.1','libclamav.so.12',package.LIBRARY_PATH])
        changed['edges'].sort()
        changed['cycles']=[['/builder/libdemo.so.1',package.LIBRARY_PATH,'/builder/libdemo.so.1']]
        # A cycle cannot be invented unless the actual builder DT_NEEDED agrees.
        with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,dependency),library)
        for cycle in [[package.LIBRARY_PATH],['/unknown','/unknown'],[package.LIBRARY_PATH,package.LIBRARY_PATH]]:
            invalid=deepcopy(doc);invalid['cycles']=[cycle]
            with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(invalid,dependency),library)

    def test_regular_ustar_only_no_extension_link_path_or_duplicate(self):
        for kind in [tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.DIRTYPE,tarfile.XHDTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_SPARSE]:
            raw=archive([('inventory.json',b'{}')],kinds={'inventory.json':kind})
            with self.assertRaises(package.PackageUnavailable):package._closure_members(raw)
        for name in ['../inventory.json','/inventory.json','lib/../x','lib/tree/x','lib/a\\b','lib/C:x']:
            with self.assertRaises(package.PackageUnavailable):package._closure_members(archive([(name,b'x')]))
        with self.assertRaises(package.PackageUnavailable):package._closure_members(archive([('inventory.json',b'{}'),('inventory.json',b'{}')]))

    def test_archive_checksum_padding_end_and_bounds(self):
        doc,library,dependency=fixture();raw=packed(doc,dependency)
        checksum=bytearray(raw);checksum[42]^=1
        pad=bytearray(raw);pad[512+len(encoded(doc))]=1
        for value in [None,b'',raw[:-1],raw[:512],bytes(checksum),bytes(pad),raw+archive([('inventory.json',b'{}')]),raw+b'x'*512]:
            with self.assertRaises(package.PackageUnavailable):package.closure_context(value,library)

    def test_bounded_closed_json_duplicates_nonfinite_and_tree(self):
        for raw in [b'{"schema":1,"schema":1}',b'{"x":NaN}',b'[ '*18+b'0'+b']'*18,b'x'*262145]:
            with self.assertRaises(package.PackageUnavailable):package._document(raw)

    def test_incomplete_or_supplied_runtime_refused_before_other_parsing(self):
        with patch.object(package,'_runtime',side_effect=AssertionError('too early')):
            for artifacts in [{},{'runtime.json':b'caller output'},None]:
                with self.assertRaises(package.PackageUnavailable):package.assemble_runtime(artifacts,b'x',b'x',b'x',clammspack_bytes=b'x',runtime_recipe=RUNTIME_RECIPE,now=datetime.now(timezone.utc))

    def test_actual_module_pins_rejected_before_generation_or_lock(self):
        artifacts={name:b'not actual artifact' for name in package.build.ARTIFACTS-{'runtime.json'}}
        with patch.object(package.build,'signature_generation',side_effect=AssertionError('must check module bytes first')):
            with self.assertRaises(package.PackageUnavailable):package.assemble_runtime(artifacts,b'library',b'patch',b'recipe',clammspack_bytes=b'companion',runtime_recipe=RUNTIME_RECIPE,now=datetime.now(timezone.utc))

    def test_runtime_configuration_uses_actual_bytes_and_receipt_before_any_lock(self):
        module_dir=Path('backend/apps/operations')
        artifacts={'kapit_evidence/'+name:(b'' if name=='__init__.py' else (module_dir/name).read_bytes()) for name in package.build.MODULE_PINS}
        receipt=b'synthetic receipt, not signature authentication'
        artifacts['signature-verification.json']=receipt
        rows=[]
        for name in sorted(package.build.CVDS):
            artifacts[name]=('synthetic '+name).encode()
            rows.append({'name':name,'sha256':package.build.sha256(artifacts[name]),'version':1,'signed_at':'2026-10-22T00:00:00Z','verification_receipt_sha256':package.build.sha256(receipt)})
        artifacts['signature-files.json']=encoded(rows)
        now=datetime(2026,10,22,1,tzinfo=timezone.utc)
        with patch.object(package.build,'parse_lock',side_effect=AssertionError('no lock yet')):
            runtime,generation=package._runtime(artifacts,b'actual synthetic library bytes',now=now)
        value=json.loads(runtime)
        self.assertEqual(value['files']['clamav'],package.build.sha256(b'actual synthetic library bytes'))
        self.assertEqual(value['signature_generation'],generation)
        artifacts['signature-verification.json']+=b'drift'
        with self.assertRaises(package.PackageUnavailable):package._runtime(artifacts,b'library',now=now)

    def test_runtime_result_is_frozen_and_never_eligible(self):
        result=package.RuntimePackage(b'lock',b'config',MappingProxyType({'Dockerfile':b'fixed'}))
        self.assertFalse(result.runtime_eligible)
        with self.assertRaises(TypeError):result.files['other']=b'x'
        with self.assertRaises(FrozenInstanceError):result.lock_raw=b'changed'
        with self.assertRaises(TypeError):package.RuntimePackage(b'a',b'b',MappingProxyType({}),runtime_eligible=True)

    def test_actual_builder_elf_soname_and_needed_edges_not_only_declared_hash(self):
        doc,library,dependency=fixture()
        for wrong in [image(soname='libother.so.1'),image(soname='libdemo.so.1',needed=('libabsent.so.1',))]:
            changed=deepcopy(doc);changed['inventory'][0]['sha256']=package.build.sha256(wrong);changed['inventory'][0]['size']=len(wrong)
            with self.assertRaises(package.PackageUnavailable):package.closure_context(packed(changed,wrong),library)

    def test_entire_wheel_elf_set_derived_not_supplied_subset(self):
        sink=io.BytesIO();records={}
        with zipfile.ZipFile(sink,'w') as output:
            for index in range(26):
                name='PIL/module'+str(index)+'.so';raw=image(soname='module'+str(index)+'.so')
                output.writestr(name,raw)
                records[package.WHEEL_ROOT+name]={'sha256':package.build.sha256(raw),'size':len(raw),'soname':'module'+str(index)+'.so'}
            output.writestr('pillow.dist-info/METADATA',b'synthetic semantic wheel fixture only')
        wheel=sink.getvalue()
        # This fixture is intentionally not the official full-input positive.
        # Production compares the actual unchanged source pins before opening ZIP.
        with patch.object(package.build,'PILLOW_SHA256',package.build.sha256(wheel)),patch.object(package.build,'PILLOW_BYTES',len(wheel)):
            self.assertEqual(len(package._wheel_rows(wheel,records)),26)
            subset=dict(records);subset.pop(next(iter(subset)))
            with self.assertRaises(package.PackageUnavailable):package._wheel_rows(wheel,subset)
            changed=deepcopy(records);next(iter(changed.values()))['sha256']='f'*64
            with self.assertRaises(package.PackageUnavailable):package._wheel_rows(wheel,changed)
        with self.assertRaises(package.PackageUnavailable):package._wheel_rows(wheel,records)

    def test_runtime_only_recipe_cannot_recompile_and_uses_fixed_production_defaults(self):
        package._runtime_recipe(RUNTIME_RECIPE)
        text=RUNTIME_RECIPE.decode()
        self.assertEqual(sum(line.startswith('FROM ') for line in text.splitlines()),1)
        self.assertIn('FROM '+package.build.RUNTIME_IMAGE,text)
        self.assertIn('COPY clamav/ /opt/clamav/',text)
        for forbidden in ['--from=build','cmake','cargo','rust@','source.tar.gz','builder-debs','apt-get','dpkg --install']:
            self.assertNotIn(forbidden,text)
        for fixed in ['WORKDIR /scratch','USER 65532:65532','CMD []',
                      'ENTRYPOINT ["/usr/local/bin/python", "-I", "-B", "-m", "kapit_evidence.evidence_native_worker"]',
                      'python -I -B -c "from kapit_evidence.evidence_native_worker import load_configuration; load_configuration()"']:
            self.assertIn(fixed,text)
        for altered in [RUNTIME_RECIPE+b'\nRUN cmake\n',RUNTIME_RECIPE.replace(b'CMD []',b'CMD ["python3"]'),RUNTIME_RECIPE.replace(b'COPY clamav/',b'COPY --from=build /out/opt/clamav/')]:
            with self.assertRaises(package.PackageUnavailable):package._runtime_recipe(altered)

    def test_exact_two_clamav_roots_require_real_bytes_sonames_hashes_and_edges(self):
        doc,library,dependency=fixture();records={row['path']:row for row in doc['inventory']}
        companion=image(soname='libclammspack.so.0')
        records[package.COMPANION_PATH]={'path':package.COMPANION_PATH,'origin':'root','sha256':package.build.sha256(companion),'size':len(companion),'soname':'libclammspack.so.0'}
        context=package.clamav_context(records,library,companion,doc['edges'])
        self.assertEqual(set(context),{'clamav/lib/libclamav.so.12.0.3','clamav/lib/libclamav.so.12','clamav/lib/libclammspack.so.0'})
        self.assertEqual(context['clamav/lib/libclamav.so.12'],context['clamav/lib/libclamav.so.12.0.3'])
        self.assertEqual(context['clamav/lib/libclammspack.so.0'],companion)
        for changed in [None,b'not ELF',image(soname='libwrong.so.0')]:
            with self.assertRaises((package.PackageUnavailable,package.ElfUnavailable)):
                package.clamav_context(records,library,changed,doc['edges'])
        for variant in ('missing','extra','hash','needed'):
            changed=deepcopy(records);edges=deepcopy(doc['edges'])
            if variant=='missing':changed.pop(package.COMPANION_PATH)
            elif variant=='extra':changed['/opt/clamav/lib/extra.so']=changed[package.COMPANION_PATH]
            elif variant=='hash':changed[package.COMPANION_PATH]['sha256']='f'*64
            else:edges.append([package.COMPANION_PATH,'libfake.so.1',package.LIBRARY_PATH])
            with self.assertRaises(package.PackageUnavailable):package.clamav_context(changed,library,companion,edges)


if __name__=='__main__':unittest.main()
