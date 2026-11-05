"""Pure mocks and synthetic bytes; no Docker, native artifacts or filesystem writes."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from infra import evidence_interpreter_prepare as refresh
from infra import evidence_interpreter_package as package
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
    def setUp(self):
        self.production_receipts = dict(refresh.RECEIPT_PINS)
        # Synthetic constants isolate pure fixture execution; no actual run can
        # use these values and imported production placeholders remain closed.
        for name, value in (("COMPILER", "sha256:"+"b"*64), ("CONFIG", "sha256:"+"c"*64),
                            ("MAIN_SHA", "d"*64), ("BUILD", "ai/state/private-scanner-interpreter-compile-"+"a"*32+".json"),
                            ("EXPORT", "ai/state/private-scanner-export-"+"e"*32+".json")):
            self.enterContext(patch.object(refresh, name, value))
        self.enterContext(patch.object(package, "COMPILER_IMAGE", refresh.COMPILER))
        self.enterContext(patch.object(refresh, "RECEIPT_PINS", {name:"f"*64 for name in (
            refresh.BUILD, refresh.IDENTITY, refresh.EXPORT, refresh.BASE_EXPORT,
            refresh.FAILED_PARENT, refresh.BUILD_PARENT, refresh.EXPORT_PARENT)}))

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
        common={'schema':1,'scope':'PUBLIC_EXISTING_INTERPRETER_BUILD_READBACK_NOT_NATIVE_PROOF',
                'status':'VERIFIED','completed':True,'pins_closed':True,'native_eligible':False,
                'private_input_allowed':False,'control_state_modified':False}
        build['context']=refresh.COMPILE_CONTEXT
        build['context_files']={str(n):{'bytes':1,'sha256':'a'*64} for n in range(29)}
        common.update(failed_parent_retained_refused=True,failed_parent_sha256=refresh.RECEIPT_PINS[refresh.FAILED_PARENT],
                      driver_receipt=refresh.BUILD,driver_receipt_sha256=refresh.RECEIPT_PINS[refresh.BUILD],
                      context=build['context'],context_files=build['context_files'],config_digest=refresh.CONFIG,
                      source_pins={name:refresh.SOURCE_PINS[name] for name in (
                          'infra/evidence_interpreter_build.py','infra/native/Dockerfile.evidence-interpreter',
                          'infra/native/clamav_interpreter.patch')})
        docs[refresh.BUILD_PARENT]={**common,'stage':'readback','driver_receipt':refresh.BUILD,
                                   'driver_receipt_sha256':refresh.RECEIPT_PINS[refresh.BUILD]}
        docs[refresh.FAILED_PARENT]={**common,'scope':'PUBLIC_INTERPRETER_COMPILER_NOT_NATIVE_PROOF','stage':'build','status':'REFUSED','completed':False,
                                    'pins_closed':False,'failure_code':'INTERPRETER_COMPILE_REFUSED'}
        identity.update(common,stage='identity',build_receipt=refresh.BUILD,
                        source_pins={name:refresh.SOURCE_PINS[name] for name in (
                            'infra/evidence_interpreter_build.py','infra/native/Dockerfile.evidence-interpreter',
                            'infra/native/clamav_interpreter.patch')},context_files=build['context_files'],container_created=False)
        docs[refresh.EXPORT]['original_container_id']='1'*64
        docs[refresh.EXPORT_PARENT]={**identity,**common,'stage':'export','identity_sha256':refresh.RECEIPT_PINS[refresh.IDENTITY],
             'export_receipt':refresh.EXPORT,'image_id':refresh.COMPILER,'config_digest':refresh.CONFIG,
             'directory':docs[refresh.EXPORT]['directory'],'files':docs[refresh.EXPORT]['files'],
             'original_id':'1'*64,'never_started':True,'original_id_absent_verified':True}
        reader=Mock();reader.read.side_effect=lambda name: b'fixture';reader.doc.side_effect=lambda path,expected:(docs[path],b'{}')
        return reader,docs

    def test_baseline_rejects_old_identity_reservation_and_unconfirmed_cleanup(self):
        mutations=((refresh.BUILD,'cleanup_uncertain',True),(refresh.BUILD,'threads_joined',False),
                   (refresh.IDENTITY,'image_id','sha256:'+'0'*64),(refresh.IDENTITY,'reservation','other'),
                   (refresh.EXPORT,'cli_cleanup_unconfirmed',True),(refresh.EXPORT,'original_id_absent_verified',False),
                   (refresh.EXPORT,'directory',refresh.STAGE+'/export-old'))
        with patch.object(refresh,'SOURCE_PINS', {name:'fixture' for name in ('infra/evidence_interpreter_build.py','infra/native/Dockerfile.evidence-interpreter','infra/native/clamav_interpreter.patch')}), patch.object(refresh,'digest', return_value='fixture'):
            reader,_=self.baseline_reader();self.assertEqual(len(refresh.baseline(reader)),2)
            for path,key,value in mutations:
                reader,docs=self.baseline_reader();docs[path][key]=value
                with self.subTest(field=key),self.assertRaises(refresh.RefreshUnavailable):refresh.baseline(reader)

    def test_new_fixed_parent_identity_and_export_links_are_mandatory(self):
        source = {name:'fixture' for name in ('infra/evidence_interpreter_build.py',
                  'infra/native/Dockerfile.evidence-interpreter','infra/native/clamav_interpreter.patch')}
        changes = ((refresh.BUILD_PARENT,'pins_closed',False),
                   (refresh.FAILED_PARENT,'status','COMPLETE'),
                   (refresh.FAILED_PARENT,'completed',True),
                   (refresh.FAILED_PARENT,'pins_closed',True),
                   (refresh.FAILED_PARENT,'failure_code','OTHER_FAILURE'),
                   (refresh.BUILD_PARENT,'completed',False),
                   (refresh.BUILD_PARENT,'driver_receipt',refresh.BASE_EXPORT),
                   (refresh.BUILD_PARENT,'driver_receipt_sha256','0'*64),
                   (refresh.BUILD_PARENT,'control_state_modified',True),
                   (refresh.BUILD_PARENT,'failed_parent_retained_refused',False),
                   (refresh.BUILD_PARENT,'failed_parent_sha256','0'*64),
                   (refresh.BUILD_PARENT,'context',refresh.STAGE+'/oldcontext'),
                   (refresh.IDENTITY,'source_pins',{}),
                   (refresh.IDENTITY,'context_files',{}),
                   (refresh.IDENTITY,'build_receipt',refresh.BASE_EXPORT),
                   (refresh.IDENTITY,'schema',True),
                   (refresh.EXPORT_PARENT,'identity_sha256','0'*64),
                   (refresh.EXPORT_PARENT,'export_receipt',refresh.BASE_EXPORT),
                   (refresh.EXPORT_PARENT,'files',{}),
                   (refresh.EXPORT_PARENT,'original_id','2'*64),
                   (refresh.EXPORT_PARENT,'never_started',False),
                   (refresh.EXPORT_PARENT,'original_id_absent_verified',False))
        with patch.object(refresh,'SOURCE_PINS',source), patch.object(refresh,'digest',return_value='fixture'):
            reader,_ = self.baseline_reader()
            self.assertEqual(len(refresh.baseline(reader)),2)
            for path,key,value in changes:
                reader,docs = self.baseline_reader(); docs[path][key]=value
                with self.subTest(path=path,field=key), self.assertRaises(refresh.RefreshUnavailable):
                    refresh.baseline(reader)

    def test_actual_public_driver_windows_context_matches_fixed_readback(self):
        root=Path(__file__).resolve().parents[2]
        raw=(root/'ai/state/private-scanner-interpreter-compile-b8925b35c106462cb7fd4edb34afadd8.json').read_bytes()
        self.assertEqual(refresh.digest(raw),'bc89160017fafa1142665d762e8a5f58d1fd9e6ae80e212ddb4d6a30956a5024')
        actual=json.loads(raw)
        self.assertEqual(actual['context'],refresh.COMPILE_CONTEXT.replace('/','\\'))
        source={name:'fixture' for name in ('infra/evidence_interpreter_build.py',
                'infra/native/Dockerfile.evidence-interpreter','infra/native/clamav_interpreter.patch')}
        with patch.object(refresh,'SOURCE_PINS',source),patch.object(refresh,'digest',return_value='fixture'):
            reader,docs=self.baseline_reader()
            # Keep actual public path/29-row metadata; the rest of this test's
            # inventory and success receipts are explicitly synthetic.
            docs[refresh.BUILD]['context']=actual['context']
            for name in (refresh.BUILD,refresh.BUILD_PARENT,refresh.IDENTITY,refresh.EXPORT_PARENT):
                docs[name]['context_files']=actual['context_files']
            self.assertEqual(len(refresh.baseline(reader)),2)
            for wrong in (refresh.COMPILE_CONTEXT+'/',refresh.COMPILE_CONTEXT.replace('/','\\',1),
                          refresh.COMPILE_CONTEXT.replace('50db1d9b5ae84facbf2f9dc9b69c968e','0'*32)):
                docs[refresh.BUILD]['context']=wrong
                with self.subTest(context=wrong),self.assertRaises(refresh.RefreshUnavailable):
                    refresh.baseline(reader)

    def test_unbound_prepare_refuses_before_read_or_other_io(self):
        for field in ('COMPILER','CONFIG','MAIN_SHA'):
            with patch.object(refresh,field,None):
                reader=Mock()
                with self.assertRaises(refresh.RefreshUnavailable):refresh.baseline(reader)
                reader.read.assert_not_called();reader.doc.assert_not_called()
        with patch.object(refresh,'RECEIPT_PINS',{refresh.BUILD:None}):
            reader=Mock()
            with self.assertRaises(refresh.RefreshUnavailable):refresh.baseline(reader)
            reader.read.assert_not_called();reader.doc.assert_not_called()

    def test_failed_parent_has_fixed_immutable_pin_and_remains_refused(self):
        self.assertEqual(self.production_receipts[refresh.FAILED_PARENT],
                         'd1b722e60bc5eecda447422c4b505e1f57f5c0f964b67a290db0330a177e5b54')
        self.assertNotEqual(refresh.FAILED_PARENT, refresh.BUILD_PARENT)

    def test_unbound_package_inventory_and_assembly_refuse_before_work(self):
        with patch.object(package,'COMPILER_IMAGE',None), patch.object(package,'_document') as document:
            with self.assertRaises(package.PackageUnavailable):package._inventory(b'{}',{},b'x')
            document.assert_not_called()
            with self.assertRaises(package.PackageUnavailable):
                package.assemble_runtime({},b'x',b'',b'',clammspack_bytes=b'x',runtime_recipe=b'',now=NOW)

    def test_new_paths_are_disjoint_and_sources_pin_exact_new_inputs(self):
        self.assertTrue(refresh.CLOSURE.endswith('private-scanner-interpreter-closure.json'))
        self.assertTrue(refresh.INPUTS.endswith('private-scanner-interpreter-inputs.json'))
        self.assertTrue(refresh.PACKAGE.endswith('private-scanner-interpreter-package.json'))
        self.assertTrue(refresh.CLOSURE_DIR.endswith('/runtime-closure-interpreter'))
        self.assertTrue(refresh.INPUTS_DIR.endswith('/runtime-inputs-interpreter'))
        self.assertTrue(refresh.CONTEXT.endswith('/ctx-runtime-interpreter'))
        root=Path(__file__).resolve().parents[2]
        for path,digest in refresh.SOURCE_PINS.items():
            self.assertEqual(refresh.digest((root/path).read_bytes()),digest,path)

    def test_unchanged_security_helpers_and_only_declared_prepare_functions_change(self):
        # Versioned constants/import paths are declared; behavioral helper
        # changes outside the strengthened baseline are not permitted.
        root=Path(__file__).resolve().parents[2]
        before=ast.parse((root/'infra/evidence_native_refresh.py').read_bytes())
        after=ast.parse((root/'infra/evidence_interpreter_prepare.py').read_bytes())
        nodes=lambda tree:{x.name:x for x in tree.body if isinstance(x,(ast.FunctionDef,ast.ClassDef)) and x.name!='baseline'}
        original,derived=nodes(before),nodes(after)
        self.assertEqual(set(original),set(derived))
        for name,node in derived.items():
            for item in ast.walk(node):
                if isinstance(item,ast.ImportFrom) and item.module:
                    item.module=item.module.replace('evidence_interpreter_build','evidence_native_build').replace('evidence_interpreter_package','evidence_native_package')
                if isinstance(item,ast.Constant) and type(item.value) is str:
                    item.value=item.value.replace('infra/native/clamav_interpreter.patch','infra/native/clamav_strict.patch').replace('infra/native/Dockerfile.evidence-interpreter','infra/native/Dockerfile.evidence')
            self.assertEqual(ast.dump(original[name]),ast.dump(node),name)

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


class ActualPublicBaselineTests(unittest.TestCase):
    def test_final_fixed_source_and_public_receipt_chain_matches_baseline(self):
        root=Path(__file__).resolve().parents[2]
        class PublicMetadataReader:
            def read(self, name):
                # This test has no route to protected context/export bytes.
                if name not in refresh.SOURCE_PINS:
                    raise AssertionError('Unexpected non-public source read')
                return (root/name).read_bytes()

            def doc(self, name, expected):
                if name not in refresh.RECEIPT_PINS:
                    raise AssertionError('Unexpected non-public receipt read')
                raw=(root/name).read_bytes()
                if refresh.digest(raw) != expected:
                    raise AssertionError('Changed reviewed public receipt')
                return refresh.document(raw),raw

        exported,base=refresh.baseline(PublicMetadataReader())
        self.assertEqual(exported['image'],refresh.COMPILER)
        self.assertEqual(len(exported['files']),10)
        self.assertEqual(len(base['files']),12)
        self.assertEqual(package.COMPILER_IMAGE,refresh.COMPILER)
        self.assertEqual(exported['files']['/out/opt/clamav/lib/libclamav.so.12.0.3']['sha256'],refresh.MAIN_SHA)


if __name__ == '__main__':unittest.main()
