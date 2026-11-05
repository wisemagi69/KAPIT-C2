"""Pure fixed existing-build ACL/readback tests; no protected/native actions."""
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import io
import ctypes as c
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from infra import evidence_interpreter_readback as m


class ShapeTests(unittest.TestCase):
    def rows(self,protected=False):
        return [(0,3 if protected else 19,0x1f01ff,sid) for sid in ('USER','S-1-5-18','S-1-5-32-544')]
    def check(self,**kwargs):
        args=dict(owner='USER',user='USER',control=0x8004,revision=1,acl_revision=2,
                  rows=self.rows(),protected=False)
        args.update(kwargs);m.validate_acl_shape(**args)
    def test_exact_inherited_and_protected_shapes(self):
        self.check()
        self.check(control=0x9004,rows=self.rows(True),protected=True)
    def test_controls_owner_and_revision_cannot_broaden(self):
        for args in ({'owner':'OTHER'},{'control':0x8404},{'control':0x9004},{'control':4},
            {'control':0x800c},{'control':True},{'revision':2},{'revision':True},{'acl_revision':4}):
            with self.subTest(args=args),self.assertRaises(RuntimeError):self.check(**args)
    def test_every_changed_ace_attribute_refuses(self):
        for field,alternate in ((0,1),(1,3),(1,18),(1,31),(2,0x120089),(3,'EVERYONE')):
            rows=self.rows();row=list(rows[0]);row[field]=alternate;rows[0]=tuple(row)
            with self.subTest(field=field,value=alternate),self.assertRaises(RuntimeError):self.check(rows=rows)
    def test_extra_missing_reordered_non_tuple_or_bool_aces_refuse(self):
        rows=self.rows()
        for value in (rows+rows[:1],rows[:2],rows[::-1],[list(x) for x in rows],
                      [(False,*rows[0][1:]),*rows[1:]]):
            with self.assertRaises(RuntimeError):self.check(rows=value)
    def test_only_four_exact_paths_allowed(self):
        self.assertTrue(m.directory_role(m.ROOT/m.CTX))
        for name in m.DESCENDANTS:self.assertFalse(m.directory_role(m.ROOT/m.CTX/name))
        for path in (m.ROOT/m.CTX/'other',m.ROOT/m.STAGE,m.ROOT/m.CTX/'patched/libclamav/other',
                     m.ROOT/m.CTX/'../other'):
            with self.assertRaises(RuntimeError):m.directory_role(path)


class DirectoryLifecycleTests(unittest.TestCase):
    def test_open_or_initial_identity_acl_failure_closes_owned_handle(self):
        api=SimpleNamespace(k=MagicMock());api.k.CreateFileW.return_value=123;api.k.CloseHandle.return_value=True
        with patch('infra.evidence_tools.checked'),patch.object(m,'directory_identity',side_effect=RuntimeError),\
             self.assertRaises(RuntimeError):
            with m.pin_directory(api,m.ROOT/m.CTX):pass
        api.k.CloseHandle.assert_called_once_with(123)
        api.k.CloseHandle.reset_mock();api.k.CreateFileW.return_value=c.c_void_p(-1).value
        with patch('infra.evidence_tools.checked'),self.assertRaises(RuntimeError):
            with m.pin_directory(api,m.ROOT/m.CTX):pass
        api.k.CloseHandle.assert_not_called()
        api.k.CreateFileW.return_value=123
        with patch('infra.evidence_tools.checked'),patch.object(m,'directory_identity',return_value=(1,2,3)),\
             patch.object(m,'verify_acl',side_effect=[RuntimeError('initial'),None]),self.assertRaises(RuntimeError):
            with m.pin_directory(api,m.ROOT/m.CTX):pass
        api.k.CloseHandle.assert_called_once_with(123)

    def test_real_ctypes_acl_extraction_and_descriptor_failure_cleanup(self):
        for failure in (None,'get-security','null-dacl','get-ace','free'):
            dacl=c.create_string_buffer(8);c.c_ubyte.from_address(c.addressof(dacl)).value=2
            c.c_ushort.from_address(c.addressof(dacl)+4).value=3
            aces=[c.create_string_buffer(32) for _ in range(3)]
            for ace in aces:
                c.c_ubyte.from_address(c.addressof(ace)+1).value=19
                m.w.DWORD.from_address(c.addressof(ace)+4).value=0x1f01ff
            def security(handle,kind,flags,owner,group,dacl_out,sacl,descriptor):
                owner._obj.value=555;descriptor._obj.value=666
                dacl_out._obj.value=None if failure == 'null-dacl' else c.addressof(dacl)
                return 1 if failure == 'get-security' else 0
            def control(descriptor,flags,revision):flags._obj.value=0x8004;revision._obj.value=1;return True
            def get_ace(pointer,index,result):
                result._obj.value=c.addressof(aces[index]);return failure != 'get-ace'
            sids={555:'USER',**{c.addressof(ace)+8:sid for ace,sid in
                zip(aces,('USER','S-1-5-18','S-1-5-32-544'))}}
            api=SimpleNamespace(user='USER',a=SimpleNamespace(GetSecurityInfo=security,
                GetSecurityDescriptorControl=control,GetAce=get_ace),
                k=SimpleNamespace(LocalFree=MagicMock(return_value=1 if failure == 'free' else 0)),
                sid=lambda value:sids[value.value if isinstance(value,c.c_void_p) else value])
            if failure is None:m.verify_acl(api,123,protected=False)
            else:
                with self.subTest(failure=failure),self.assertRaises(RuntimeError):m.verify_acl(api,123,protected=False)
            api.k.LocalFree.assert_called_once()
    def run_pin(self,*,identity_change=False,acl_change=False,body_error=False,close_error=False):
        api=SimpleNamespace(k=MagicMock());api.k.CreateFileW.return_value=123;api.k.CloseHandle.return_value=not close_error
        identity=[(1,2,3),(1,2,4) if identity_change else (1,2,3)]
        acl=[None,RuntimeError('changed') if acl_change else None]
        with patch('infra.evidence_tools.checked',side_effect=lambda path:path),\
             patch.object(m,'directory_identity',side_effect=identity) as identity_call,\
             patch.object(m,'verify_acl',side_effect=acl) as acl_call:
            error=None
            try:
                with m.pin_directory(api,m.ROOT/m.CTX/'patched'):
                    if body_error:raise ValueError('body')
            except BaseException as caught:error=caught
        self.assertEqual(api.k.CloseHandle.call_count,1)
        self.assertTrue(all(call.args[1] == 123 for call in identity_call.call_args_list))
        self.assertTrue(all(call.args[1] == 123 for call in acl_call.call_args_list))
        return error,identity_call,acl_call
    def test_same_retained_handle_checked_twice(self):
        error,identity,acl=self.run_pin()
        self.assertIsNone(error);self.assertEqual(identity.call_count,2);self.assertEqual(acl.call_count,2)
    def test_exit_identity_and_acl_changes_refuse(self):
        for kwargs in ({'identity_change':True},{'acl_change':True}):
            self.assertIsInstance(self.run_pin(**kwargs)[0],RuntimeError)
    def test_body_failure_still_checks_identity_acl_and_closes(self):
        error,identity,acl=self.run_pin(body_error=True)
        self.assertIsInstance(error,ValueError);self.assertEqual(identity.call_count,2);self.assertEqual(acl.call_count,2)
    def test_handle_close_uncertainty_dominates(self):
        error,_,_=self.run_pin(body_error=True,close_error=True)
        self.assertEqual(str(error),'DIRECTORY_HANDLE_CLOSE_UNCONFIRMED')
    def test_low_level_identity_reparse_links_or_different_inode_refuse(self):
        from infra import evidence_tools
        info=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0,st_nlink=1,st_dev=7,st_ino=99)
        def query(handle,pointer):
            value=pointer._obj;value.attributes=0x10;value.links=1;value.volume=7;value.index_low=99
            return True
        def full_query(handle,kind,pointer,size):
            pointer._obj.volume=7
            pointer._obj.identifier[:]=(99).to_bytes(16,'little')
            return True
        api=SimpleNamespace(k=SimpleNamespace(GetFileInformationByHandle=MagicMock(side_effect=query),
            GetFileInformationByHandleEx=MagicMock(side_effect=full_query)))
        with patch.object(evidence_tools,'checked'),patch.object(Path,'stat',return_value=info):
            self.assertEqual(m.directory_identity(api,123,m.ROOT/m.CTX),(7,99,0x10,1))
            for name,value in (('st_ino',100),('st_dev',8),('st_nlink',2),
                               ('st_file_attributes',0x400),('st_mode',stat.S_IFREG)):
                changed=SimpleNamespace(**{**vars(info),name:value})
                with patch.object(Path,'stat',return_value=changed),self.assertRaises(RuntimeError):
                    m.directory_identity(api,123,m.ROOT/m.CTX)

    def full_identity(self,*,volume_delta=0,inode_delta=0,query_failed=False):
        volume=(1<<61)+12345;inode=(1<<119)+(1<<65)+98765
        info=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0,st_nlink=1,st_dev=volume,st_ino=inode)
        def query(handle,pointer):
            value=pointer._obj;value.attributes=0x10;value.links=1
            value.volume=12345;value.index_low=98765
            return True
        def full_query(handle,kind,pointer,size):
            self.assertEqual(kind,18);self.assertEqual(size,24)
            pointer._obj.volume=volume+volume_delta
            pointer._obj.identifier[:]=(inode+inode_delta).to_bytes(16,'little')
            return not query_failed
        api=SimpleNamespace(k=SimpleNamespace(GetFileInformationByHandle=MagicMock(side_effect=query),
            GetFileInformationByHandleEx=MagicMock(side_effect=full_query),CreateFileW=MagicMock(return_value=123),
            CloseHandle=MagicMock(return_value=True)))
        with patch('infra.evidence_tools.checked'),patch.object(Path,'stat',return_value=info),\
             patch.object(m,'verify_acl'):
            with m.pin_directory(api,m.ROOT/m.CTX):pass
        return api
    def test_full_file_identity_abi_and_high_bits_match_without_truncation(self):
        self.assertEqual(c.sizeof(m.FileIdentity),24)
        self.assertEqual(m.FileIdentity.volume.offset,0);self.assertEqual(m.FileIdentity.identifier.offset,8)
        api=self.full_identity()
        self.assertEqual(api.k.GetFileInformationByHandleEx.call_count,2)
        api.k.CloseHandle.assert_called_once_with(123)
    def test_full_volume_high_bit_difference_refuses(self):
        with self.assertRaises(RuntimeError):self.full_identity(volume_delta=1<<32)
    def test_full_inode_high_bit_difference_refuses(self):
        with self.assertRaises(RuntimeError):self.full_identity(inode_delta=1<<96)
    def test_full_identity_api_failure_refuses_and_closes_owned_handle(self):
        # full_identity retains the close call even when the new query fails.
        captured=[]
        original=m.directory_identity
        def capture(api,*args):captured.append(api);return original(api,*args)
        with patch.object(m,'directory_identity',side_effect=capture),self.assertRaises(RuntimeError):
            self.full_identity(query_failed=True)
        captured[0].k.CloseHandle.assert_called_once_with(123)


class ReadbackTests(unittest.TestCase):
    def test_identity_success_and_refused_saved_provenance(self):
        compiler,refresh=m.modules()
        build=json.loads(Path(m.DRIVER_RECEIPT).read_text(encoding='utf-8'))
        saved=self.passed();saved['context_files']=build['context_files']
        actual={'Id':'sha256:'+'a'*64,'Descriptor':{'digest':'sha256:'+'a'*64},'RootFS':{'Layers':[]}}
        with patch.object(refresh,'pin_bytes',side_effect=lambda *a,**k:json.dumps(saved).encode()),\
             patch.object(compiler,'inspect_image',return_value=actual):
            result={};self.assertEqual(m.identity(None,None,None,build,result),actual)
            self.assertEqual(result['build_receipt'],m.DRIVER_RECEIPT)
            self.assertEqual(result['config_digest'],m.CONFIG)
            saved['pins_closed']=False
            with self.assertRaises(RuntimeError):m.identity(None,None,None,build,{})

    def test_export_exact_ten_original_owned_outputs_and_uncertain_cleanup_refusal(self):
        compiler,refresh=m.modules()
        actual={'Id':'sha256:'+'a'*64,'Descriptor':{'digest':'sha256:'+'a'*64},'RootFS':{'Layers':[]}}
        saved=dict(self.passed(),stage='identity',image_id=actual['Id'],descriptor=actual['Descriptor'],rootfs=actual['RootFS'])
        for uncertain in (False,True):
            owners=[]
            class Exporter:
                def __init__(self,image,kind):
                    self.receipt=m.ROOT/'ai/state/private-scanner-export-fixture.json'
                    self.directory=m.ROOT/m.STAGE/'export-fixture';self.rows={};self.cid='b'*64
                    self.cleaned=True;self.cli_uncertain=uncertain;self.closed=False;owners.append(self)
                def __enter__(self):return self
                def __exit__(self,*args):self.closed=True
                def copy(self,path):self.rows[path]={'fixture':True};return b'public'
            with patch.object(m,'identity',return_value=actual),\
                 patch.object(refresh,'pin_bytes',return_value=json.dumps(saved).encode()),\
                 patch.object(compiler,'load_fixed',return_value={'Exporter':Exporter}):
                result={}
                if uncertain:
                    with self.assertRaises(RuntimeError):m.export(None,None,None,{'ai/state/private-scanner-export.py':b'fixed'},{},result)
                else:
                    m.export(None,None,None,{'ai/state/private-scanner-export.py':b'fixed'},{},result)
                    self.assertEqual(set(result['files']),set(compiler.EXPORT_PATHS))
                    self.assertTrue(result['never_started']);self.assertTrue(result['original_id_absent_verified'])
                self.assertTrue(owners[0].closed)
    def passed(self):
        compiler,_=m.modules()
        return {'schema':1,'scope':m.SCOPE,'stage':'readback','status':'VERIFIED','completed':True,
            'pins_closed':True,'failed_parent_retained_refused':True,'failed_parent_sha256':m.FAILED_SHA,
            'driver_receipt':m.DRIVER_RECEIPT,'driver_receipt_sha256':m.DRIVER_SHA,'config_digest':m.CONFIG,
            'source_pins':dict(compiler.NEW_PINS),'native_eligible':False,'private_input_allowed':False,
            'control_state_modified':False}
    def test_new_provenance_never_relabels_failed_parent(self):
        value=self.passed();m.validate_readback(value)
        for key,wrong in (('status','COMPLETE'),('completed',False),('pins_closed',False),
            ('failed_parent_retained_refused',False),('failed_parent_sha256','0'*64),
            ('driver_receipt_sha256','0'*64),('native_eligible',True),('schema',True)):
            with self.subTest(key=key),self.assertRaises(RuntimeError):m.validate_readback(dict(value,**{key:wrong}))
    def test_fixed_original_parent_and_driver_hashes(self):
        compiler,refresh=m.modules()
        rows={m.FAILED_PARENT:Path(m.FAILED_PARENT).read_bytes(),m.DRIVER_RECEIPT:Path(m.DRIVER_RECEIPT).read_bytes()}
        calls=[]
        def read(root,pins,api,name,**kwargs):
            calls.append((name,kwargs['expected']));return rows[name]
        with patch.object(refresh,'pin_bytes',side_effect=read):value=m.fixed_build(None,None)
        self.assertEqual(value['iidfile'],m.CONFIG)
        self.assertEqual(calls,[(m.FAILED_PARENT,m.FAILED_SHA),(m.DRIVER_RECEIPT,m.DRIVER_SHA)])
    def test_no_build_command_and_fixed_cli(self):
        import ast
        source=Path(m.__file__).read_text(encoding='utf-8');tree=ast.parse(source)
        calls=[ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node,ast.Call)]
        self.assertNotIn('compiler.build_stage',calls)
        self.assertNotIn('subprocess.Popen',calls)
        with self.assertRaises(SystemExit):m.main(['build'])
    def test_exclusive_readback_refuses_before_any_input_access(self):
        compiler,refresh=m.modules()
        for stage in ('readback','identity','export'):
            with patch.object(refresh,'Receipt',side_effect=FileExistsError),\
                 patch.object(compiler,'checked_inputs',side_effect=AssertionError),self.assertRaises(FileExistsError):
                m.execute(stage)
    def test_changed_actual_context_bytes_flow_real_hash_pin(self):
        from infra import evidence_interpreter_build as build
        compiler,refresh=m.modules()
        prior=json.loads(Path(m.DRIVER_RECEIPT).read_text(encoding='utf-8'))
        files={name:b'public' for name in prior['context_files']}
        value={'context_files':{name:{'bytes':6,'sha256':compiler.digest(b'public')} for name in files}}
        original=refresh.pin_bytes
        class API:
            def pin(self,*args,**kwargs):return nullcontext(io.BytesIO(b'changed'))
        def read(root,pins,api,name,**kwargs):
            return original(root,pins,api,name,**kwargs) if name.startswith(m.CTX+'/') else b'input'
        with patch.object(build,'source_build_inputs',return_value=SimpleNamespace(files=files)),\
             patch.object(refresh,'pin_bytes',side_effect=read),\
             patch.object(m,'pin_directory',return_value=nullcontext()),\
             ExitStack() as pins,self.assertRaises(refresh.RefreshUnavailable):
            m.reconstructed_context(API(),pins,value)
    def test_context_pins_all_four_ancestors_and_exact_29_bytes(self):
        self.context(False)
    def test_changed_context_row_refuses_before_directory_open(self):
        self.context(True)
    def context(self,changed):
        from infra import evidence_interpreter_build as build
        compiler,refresh=m.modules();events=[]
        prior=json.loads(Path(m.DRIVER_RECEIPT).read_text(encoding='utf-8'))
        files={name:b'public' for name in prior['context_files']}
        rows={name:{'bytes':6,'sha256':compiler.digest(b'public')} for name in files}
        value={'context_files':deepcopy(rows)}
        if changed:value['context_files']['Dockerfile']['bytes']=7
        @contextmanager
        def directory(api,path):
            events.append(('open',path))
            try:yield
            finally:events.append(('close',path))
        reads=[]
        def read(root,pins,api,name,**kwargs):
            reads.append((name,kwargs));return b'public'
        with patch.object(build,'source_build_inputs',return_value=SimpleNamespace(files=files)),\
             patch.object(refresh,'pin_bytes',side_effect=read),patch.object(m,'pin_directory',side_effect=directory):
            if changed:
                with ExitStack() as pins,self.assertRaises(RuntimeError):m.reconstructed_context(None,pins,value)
                self.assertEqual(events,[])
            else:
                with ExitStack() as pins:m.reconstructed_context(None,pins,value)
                expected=[m.ROOT/m.CTX/rel for rel in ('',*m.DESCENDANTS)]
                self.assertEqual(events,[('open',p) for p in expected]+[('close',p) for p in reversed(expected)])
                contexts=[(n,k) for n,k in reads if n.startswith(m.CTX+'/')]
                self.assertEqual(len(contexts),29)
                self.assertTrue(all(k['private'] is True and k['expected'] == compiler.digest(b'public') for _,k in contexts))


class ExecutionTests(unittest.TestCase):
    def run_fake(self,*,pin_close_failure=False,receipt_close_failure=False,stale=False,wrong_engine=False,deadline=False):
        compiler,refresh=m.modules();events=[];saved=[]
        class Receipt:
            def __init__(self,*args):self.stream=SimpleNamespace(closed=False);self.closes=0
            def save(self,value):saved.append(deepcopy(value))
            def close(self):
                self.closes+=1
                if receipt_close_failure and self.closes == 1:raise OSError('close')
                self.stream.closed=True
        @contextmanager
        def inputs():
            try:yield None,None,None,{'ai/state/private-scanner-resume-pcre.py':b'fixed'}
            finally:
                if pin_close_failure:raise OSError('pins')
        class Observation:
            result={'engine_sha256':'0'*64 if wrong_engine else compiler.modules()[1].ENGINE}
            def consume(self):
                events.append('builder-consume')
                if stale:raise RuntimeError('stale')
        @contextmanager
        def observe():events.append('builder-observe');yield Observation()
        def oldlive(call):
            events.append('old-live')
            return SimpleNamespace(consume=lambda:events.append('original-consume'))
        fakebuild=json.loads(Path(m.DRIVER_RECEIPT).read_text(encoding='utf-8'))
        with patch.object(refresh,'Receipt',Receipt),patch.object(compiler,'checked_inputs',inputs),\
             patch.object(refresh,'pin_bytes'),patch.object(m,'fixed_build',return_value=fakebuild),\
             patch.object(m,'reconstructed_context',side_effect=lambda *args:events.append('context')),\
             patch.object(compiler,'load_fixed',return_value={'live_postflight_module':lambda *args:{'observe':observe}}),\
             patch.object(compiler,'live_originals',side_effect=oldlive),\
             patch.object(m.time,'monotonic',side_effect=[0,301,302] if deadline else [0,1,2]):
            error=None
            try:result=m.execute('readback')
            except BaseException as caught:error=caught;result=saved[-1]
        return result,error,events
    def test_success_separate_from_failed_parent(self):
        result,error,events=self.run_fake()
        self.assertIsNone(error);self.assertEqual(result['status'],'VERIFIED')
        self.assertTrue(result['failed_parent_retained_refused'])
        self.assertEqual(events[:5],['context','builder-observe','old-live','original-consume','builder-consume'])
    def test_pin_and_receipt_close_failures_override_success(self):
        for kwargs in ({'pin_close_failure':True},{'receipt_close_failure':True}):
            result,error,_=self.run_fake(**kwargs)
            self.assertIsNotNone(error);self.assertEqual(result['status'],'REFUSED');self.assertFalse(result['completed'])
    def test_stale_builder_refuses_existing_build_readback(self):
        result,error,_=self.run_fake(stale=True)
        self.assertIsNotNone(error);self.assertFalse(result['completed'])
    def test_wrong_engine_or_final_deadline_refuses(self):
        for kwargs in ({'wrong_engine':True},{'deadline':True}):
            result,error,_=self.run_fake(**kwargs)
            self.assertIsNotNone(error);self.assertEqual(result['status'],'REFUSED')


if __name__ == '__main__':unittest.main()
