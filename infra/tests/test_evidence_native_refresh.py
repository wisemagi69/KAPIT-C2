"""Pure mocks and synthetic bytes; no Docker, native artifacts or filesystem writes."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from infra import evidence_native_refresh as refresh
from infra import evidence_native_package as package
from infra.test_evidence_elf import image

NOW = datetime(2026,10,22,1,tzinfo=timezone.utc)


class MemoryAPI:
    def __init__(self, files=None, close_failure=False):
        self.files = files or {}; self.close_failure = close_failure; self.pinned = []

    @contextmanager
    def pin(self, path, **kwargs):
        self.pinned.append((str(path), kwargs))
        yield None if kwargs.get('directory') else io.BytesIO(self.files[str(path)])
        if self.close_failure: raise refresh.RefreshUnavailable()


class RefreshTests(unittest.TestCase):
    def test_parser_rejects_duplicate_nan_and_excessive_depth(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'['*18+b'0'+b']'*18, b'{}'*140000):
            with self.subTest(raw=raw[:30]), self.assertRaises(refresh.RefreshUnavailable): refresh.document(raw)
        self.assertEqual(refresh.document(b'{"schema":1}'), {'schema':1})

    def test_path_rejects_traversal_drive_unc_normalization_and_alt_stream(self):
        for value in ('../x','a/../x','/tmp/x','C:/x','a\\x','//host/x','a//x','a/./x','a:x','.','a/','a\x00','x.','a/NUL','COM1.txt'):
            with self.subTest(path=value), self.assertRaises(refresh.RefreshUnavailable): refresh.safe_name(value)
        self.assertEqual(refresh.safe_name('closure/lib/libdemo.so.1'), 'closure/lib/libdemo.so.1')
        self.assertEqual(refresh.safe_name(refresh.CONTEXT+'/runtime.json'), refresh.CONTEXT+'/runtime.json')

    def test_checked_row_rejects_changed_bytes_hash_size_bool_and_path_row(self):
        raw = b'public'; row = {'bytes':len(raw),'sha256':refresh.digest(raw)}
        self.assertEqual(refresh.checked_row(raw,row), raw)
        for invalid in ({**row,'bytes':True}, {**row,'bytes':2}, {**row,'sha256':'g'*64}, {**row,'sha256':'a'*64}):
            with self.assertRaises(refresh.RefreshUnavailable): refresh.checked_row(raw, invalid)

    def test_reader_holds_parent_and_source_handles_and_refuses_hash_mismatch(self):
        root = Path('/synthetic'); api = MemoryAPI({str(root/'src/test.py'):b'file'})
        with ExitStack() as stack:
            reader = refresh.Reader(root, stack, api)
            self.assertEqual(reader.read('src/test.py'), b'file')
            self.assertEqual(len(api.pinned),3)
            with self.assertRaises(refresh.RefreshUnavailable): reader.read('src/test.py', {'bytes':4,'sha256':'a'*64})

    def test_public_original_in_protected_stage_uses_exact_parent_acl_without_requiring_file_acl(self):
        root=Path('/synthetic');path=refresh.STAGE+'/pillow.whl'
        api=MemoryAPI({str(root/path):b'public'})
        with ExitStack() as stack:
            self.assertEqual(refresh.Reader(root,stack,api).read(path),b'public')
            stage_pins=[options for name,options in api.pinned if name==str(root/refresh.STAGE)]
            self.assertEqual(stage_pins,[{'directory':True,'private':True}])
            self.assertFalse(api.pinned[-1][1]['private'])

    def test_reader_bounded_duplicate_document_and_pin_close_failure(self):
        root = Path('/synthetic'); api = MemoryAPI({str(root/'x'):b'{"a":0,"a":1}'})
        with ExitStack() as stack:
            with self.assertRaises(refresh.RefreshUnavailable): refresh.Reader(root,stack,api).doc('x')
        with self.assertRaises(refresh.RefreshUnavailable):
            with ExitStack() as stack:
                refresh.Reader(root,stack,MemoryAPI({str(root/'x'):b'x'},True)).read('x')

    def baseline_reader(self):
        build={'compiler_success':True,'reason':'EXIT','exit':0,'cli_reaped':True,'threads_joined':True,'streams_closed':True,
               'cleanup_uncertain':False,'iidfile':refresh.CONFIG,'reservation':'r','tag':'tag'}
        identity={'image_id':refresh.COMPILER,'config_digest':refresh.CONFIG,'build_receipt_sha256':refresh.RECEIPT_PINS[refresh.BUILD],
                  'reservation':'r','tag':'tag','descriptor':{'digest':refresh.COMPILER,'annotations':{'config.digest':refresh.CONFIG}}}
        def exported(path,kind,image,count):
            token=path.rsplit('-',1)[1].removesuffix('.json')
            return {'scope':'PUBLIC_ARTIFACT_EXPORT','kind':kind,'image':image,'reservation':token,'never_started':True,
                    'original_id_absent_verified':True,'cleanup_status':'ORIGINAL_ID_ABSENT_VERIFIED','cli_cleanup_unconfirmed':False,
                    'directory':refresh.STAGE+'/export-'+token,'native_eligible':False,
                    'files':{str(i):{'local_name':'artifact-'+str(i)} for i in range(count)}}
        docs={refresh.BUILD:build,refresh.IDENTITY:identity,refresh.EXPORT:exported(refresh.EXPORT,'compiler',refresh.COMPILER,10),
              refresh.BASE_EXPORT:exported(refresh.BASE_EXPORT,'python-base',refresh.BASE,12)}
        reader=Mock();reader.doc.side_effect=lambda path,expected:(docs[path],b'{}')
        return reader,docs

    def test_baseline_rejects_old_identity_reservation_and_unconfirmed_cleanup(self):
        mutations=((refresh.BUILD,'cleanup_uncertain',True),(refresh.BUILD,'threads_joined',False),
                   (refresh.IDENTITY,'image_id','sha256:'+'0'*64),(refresh.IDENTITY,'reservation','other'),
                   (refresh.EXPORT,'cli_cleanup_unconfirmed',True),(refresh.EXPORT,'original_id_absent_verified',False),
                   (refresh.EXPORT,'directory',refresh.STAGE+'/export-old'))
        with patch.object(refresh,'SOURCE_PINS',{}):
            reader,_=self.baseline_reader();self.assertEqual(len(refresh.baseline(reader)),2)
            for path,key,value in mutations:
                reader,docs=self.baseline_reader();docs[path][key]=value
                with self.subTest(field=key),self.assertRaises(refresh.RefreshUnavailable):refresh.baseline(reader)

    def test_reader_exact_receipt_hash_required_even_with_pass_payload(self):
        root=Path('/synthetic');api=MemoryAPI({str(root/'x'):b'{"success":true}'})
        with ExitStack() as stack:
            with self.assertRaises(refresh.RefreshUnavailable):refresh.Reader(root,stack,api).doc('x','0'*64)

    def test_package_validator_accepts_fresh_identity_rejects_historical_identity(self):
        library = image(soname='libclamav.so.12',needed=('libdemo.so.1',)); dependency = image(soname='libdemo.so.1')
        def row(path, origin, data, soname):
            return {'path':path,'origin':origin,'sha256':refresh.digest(data),'size':len(data),'soname':soname}
        doc = {'schema':1,'scope':'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF','compiler_image':refresh.COMPILER,
               'runtime_base':refresh.BASE,'inventory':[row('/builder/libdemo.so.1','builder',dependency,'libdemo.so.1'),row(package.LIBRARY_PATH,'root',library,'libclamav.so.12')],
               'edges':[[package.LIBRARY_PATH,'libdemo.so.1','/builder/libdemo.so.1']],'cycles':[],
               'export_receipts':[refresh.EXPORT,refresh.BASE_EXPORT],'native_executed':False,'native_eligible':False}
        files={'inventory.json':refresh.canonical(doc),'lib/libdemo.so.1':dependency}
        self.assertIn(package.LIBRARY_PATH, package._inventory(files['inventory.json'],files,library))
        doc['compiler_image']='sha256:3635be44be35fc4b3ad0312b136d87ffbcdac2b5f11d83a4c3160451722aed6c'
        with self.assertRaises(package.PackageUnavailable): package._inventory(refresh.canonical(doc), files, library)

    def signature_reader(self, *, checked=NOW-timedelta(hours=1), daily=NOW-timedelta(hours=3)):
        files = {}; rows=[]
        for name in ('bytecode.cvd','daily.cvd','main.cvd'):
            raw = name.encode(); files[name] = raw
            rows.append({'name':name,'bytes':len(raw),'sha256':refresh.digest(raw),'version':1,
                         'built_utc':(daily if name=='daily.cvd' else NOW-timedelta(days=30)).isoformat(),
                         'signature_verification':'VERIFIED','verification_exit':0})
        doc={'native_exit':0,'code':'UPDATER_COMPLETED','activation':'INACTIVE','native_validation':'DISABLED',
             'all_cvd_signatures_verified':True,'executed_at_utc':checked.isoformat(),'definition_files':rows}
        reader = Mock(); reader.doc.return_value=(doc,refresh.canonical(doc))
        reader.read.side_effect=lambda path,row,**kw:refresh.checked_row(files[path.rsplit('/',1)[1]],row)
        return reader

    def test_signature_freshness_recomputed_not_saved_ready_flag(self):
        reader=self.signature_reader(); files,generation,verification=refresh.signatures(reader,NOW)
        self.assertEqual(len(files),5); self.assertRegex(generation,r'^[0-9a-f]{64}$')
        self.assertEqual(verification,refresh.digest(reader.doc.return_value[1]))
        for reader in (self.signature_reader(checked=NOW-timedelta(hours=24)),self.signature_reader(checked=NOW+timedelta(seconds=1)),
                       self.signature_reader(daily=NOW-timedelta(hours=72)),self.signature_reader(daily=NOW+timedelta(seconds=1))):
            with self.assertRaises(refresh.RefreshUnavailable): refresh.signatures(reader,NOW)

    def test_signature_forged_verification_and_duplicate_rows_refused(self):
        for mutate in (lambda d:d.update(activation='ACTIVE'),lambda d:d.update(all_cvd_signatures_verified=False),
                       lambda d:d['definition_files'][0].update(verification_exit=1),
                       lambda d:d['definition_files'].__setitem__(0,d['definition_files'][1])):
            reader=self.signature_reader(); mutate(reader.doc.return_value[0])
            with self.assertRaises(refresh.RefreshUnavailable): refresh.signatures(reader,NOW)

    def staged(self):
        return {'schema':1,'scope':'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF','compiler_image':refresh.COMPILER,
                'main_library_sha256':refresh.MAIN_SHA,'source_pins':refresh.SOURCE_PINS,'native_eligible':False,'control_state_modified':False,
                'upstream_receipts':refresh.RECEIPT_PINS,'directory':refresh.CLOSURE_DIR,'files':{'inventory.json':{'bytes':2,'sha256':refresh.digest(b'{}')}}}

    def test_staged_refuses_old_compiler_unknown_directory_incomplete_sources_extra_schema(self):
        reader=Mock(); reader.read.return_value=b'{}'
        self.assertEqual(refresh.read_staged(reader,self.staged(),refresh.CLOSURE_DIR),{'inventory.json':b'{}'})
        for updates in ({'directory':refresh.STAGE+'/runtime-closure2'},{'compiler_image':'sha256:'+'0'*64},
                        {'source_pins':{}},{'native_eligible':True},{'control_state_modified':True},{'unexpected':1},{'schema':True}):
            doc=self.staged();doc.update(updates)
            with self.assertRaises(refresh.RefreshUnavailable): refresh.read_staged(reader,doc,refresh.CLOSURE_DIR)

    def test_staged_unsafe_member_refused_before_any_read(self):
        reader=Mock(); doc=self.staged();doc['files']={'../old':{'bytes':1,'sha256':'a'*64}}
        with self.assertRaises(refresh.RefreshUnavailable): refresh.read_staged(reader,doc,refresh.CLOSURE_DIR)
        reader.read.assert_not_called()

    def test_execute_success_after_all_pin_closes_and_never_on_close_failure(self):
        for fail in (False, True):
            events=[]; api=MemoryAPI(close_failure=fail)
            def fake_baseline(reader):
                reader.pins.enter_context(api.pin('/fake',directory=True));return {},{}
            with patch.object(refresh,'baseline',side_effect=fake_baseline),patch.object(refresh,'closure_files',return_value={'inventory.json':b'{}'}),\
                 patch.object(refresh,'write_files',side_effect=lambda *a:events.append('files')),\
                 patch.object(refresh,'write_exclusive',side_effect=lambda *a:events.append('receipt')),\
                 patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),\
                 patch.object(refresh.shutil,'disk_usage',return_value=SimpleNamespace(free=4*1024**3)):
                if fail:
                    with self.assertRaises(refresh.RefreshUnavailable):refresh.execute('closure','/synthetic',api,Mock(),now=NOW)
                    self.assertEqual(events,['files'])
                else:
                    result=refresh.execute('closure','/synthetic',api,Mock(),now=NOW)
                    self.assertEqual(events,['files','receipt']);self.assertFalse(result['native_eligible'])

    def test_execute_existing_receipt_or_partial_context_refuses_overwrite(self):
        with patch.object(Path,'exists',return_value=True),patch.object(refresh,'write_exclusive') as write:
            with self.assertRaises(refresh.RefreshUnavailable):refresh.execute('closure','/synthetic',Mock(),Mock())
            write.assert_not_called()
        reader=Mock();reader.root=Path('/synthetic')
        with patch.object(Path,'exists',return_value=True),patch.object(refresh,'write_exclusive') as write:
            private=Mock()
            with self.assertRaises(refresh.RefreshUnavailable):refresh.write_files(reader,refresh.CONTEXT,{'x':b'x'},private)
            private.create.assert_not_called();write.assert_not_called()

    def test_execute_output_failure_never_emits_success_receipt(self):
        with patch.object(refresh,'baseline',return_value=({},{})),patch.object(refresh,'closure_files',return_value={'inventory.json':b'{}'}),\
             patch.object(refresh,'write_files',side_effect=OSError()),patch.object(refresh,'write_exclusive') as write,\
             patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(refresh.shutil,'disk_usage',return_value=SimpleNamespace(free=4*1024**3)):
            with self.assertRaises(OSError):refresh.execute('closure','/synthetic',Mock(),Mock(),now=NOW)
            write.assert_not_called()

    def test_verified_package_rejects_image_generation_context_and_lock_substitution(self):
        raw=SimpleNamespace(files={'runtime.json':b'{}'},runtime_json=b'{}',lock_raw=b'lock')
        receipt={**self.staged(),'scope':'PUBLIC_FINAL_RUNTIME_BUILD_INPUTS_NOT_NATIVE_PROOF','directory':refresh.CONTEXT,
                 'files':refresh.rows(dict(raw.files)),'signature_generation':'a'*64,'lock_path':refresh.LOCK,
                 'lock_sha256':refresh.digest(raw.lock_raw),'runtime_json_sha256':refresh.digest(raw.runtime_json)}
        for updates in ({},{'signature_generation':'b'*64},{'runtime_json_sha256':'b'*64},{'lock_path':refresh.STAGE+'/old-lock.json'},
                        {'upstream_receipts':{}},{'compiler_image':'sha256:'+'0'*64}):
            changed=deepcopy(receipt);changed.update(updates)
            reader=Mock();reader.doc.return_value=(changed,b'{}');reader.read.return_value=raw.lock_raw
            with patch.object(refresh,'Reader',return_value=reader),patch.object(refresh,'baseline',return_value=({},{})),\
                 patch.object(refresh,'read_staged',wraps=lambda r,d,p: (refresh.require(d['compiler_image']==refresh.COMPILER) or dict(raw.files))),\
                 patch.object(refresh,'package_files',return_value=(raw,'a'*64,refresh.RECEIPT_PINS)):
                with ExitStack() as pins:
                    if updates:
                        with self.assertRaises(refresh.RefreshUnavailable):refresh.verified_package('/synthetic',pins,Mock(),now=NOW)
                    else:self.assertEqual(refresh.verified_package('/synthetic',pins,Mock(),now=NOW),receipt)


if __name__ == '__main__':unittest.main()
