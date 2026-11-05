"""Pure compiler-controller invariants; no native/protected/daemon access."""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
import json
import io
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from infra import evidence_interpreter_compile as m


class TransformTests(unittest.TestCase):
    def raw(self):
        return Path(m.DRIVER).read_bytes()

    def test_exact_reviewed_transform_is_compilable(self):
        source = m.prepared_driver(self.raw(), '1'*32)
        compile(source, '<pure>', 'exec')
        self.assertIn("CTX=STAGE/'ctx-interpreter-"+'1'*32+"'",source)
        self.assertIn('from infra.evidence_interpreter_build import',source)
        self.assertNotIn('infra/native/clamav_strict.patch',source)

    def test_preserves_runtime_and_cleanup_body(self):
        old = self.raw().decode('utf-8')
        source = m.prepared_driver(self.raw(), '2'*32)
        self.assertEqual(old[old.index('  args=['):], source[source.index('  args=['):])
        self.assertIn('free>=MIN_BUILD_FREE_BYTES',source)
        self.assertIn('elapsed>=900',source)
        self.assertIn('2*1024*1024',source)
        self.assertIn("--network','none'",source)

    def test_changed_original_refuses(self):
        for raw in (self.raw()+b' ',b'',self.raw().replace(b'900',b'901')):
            with self.subTest(raw=len(raw)), self.assertRaises(m.Refused):
                m.prepared_driver(raw,'1'*32)

    def test_reservation_cannot_inject_source(self):
        for token in ('', '1'*31, '1'*33, 'A'*32, "x';bad()#", True, None):
            with self.subTest(token=token), self.assertRaises(m.Refused):
                m.prepared_driver(self.raw(),token)

    def test_incomplete_or_invalid_new_pins_closed(self):
        for pins in ({}, {**m.NEW_PINS,'extra':'0'*64},
                     {**m.NEW_PINS,m.PIN_NAMES[0]:None}):
            with patch.object(m,'NEW_PINS',pins), self.assertRaises(m.Refused):
                m.prepared_driver(self.raw(),'1'*32)

    def test_fixed_loader_rejects_other_sources_before_exec(self):
        for name,raw in ((m.DRIVER,self.raw()),('arbitrary.py',b'raise AssertionError'),
                         ('ai/state/private-scanner-export.py',b'raise AssertionError')):
            with self.assertRaises(m.Refused): m.load_fixed(name,raw)


class LiveTests(unittest.TestCase):
    def selectors(self):
        _,old,_,_ = m.modules()
        return old, (old.OLD_CID,old.OLD_NAME,m.CID,m.NAME)

    def absent_response(self, selector):
        return 1,b'[]\n',('Error response from daemon: No such container: '+selector+'\n').encode(), 'EXIT'

    def test_exact_missing_shapes_accepted(self):
        _,selectors = self.selectors()
        for selector in selectors:
            m.absent(lambda *args:self.absent_response(selector),selector)

    def test_unknown_selector_never_queries(self):
        def call(*args): raise AssertionError('must not query')
        with self.assertRaises(m.Refused):m.absent(call,'other')

    def test_presence_error_bool_and_stderr_spoof_refuse(self):
        for response in ((0,b'[{}]',b'','EXIT'), (True,b'[]',b'','EXIT'),
                         (1,b'[]',b'permission denied','EXIT'),
                         (1,b'[]',self.absent_response(m.CID)[2],'TIMEOUT'),
                         self.absent_response(m.NAME)):
            with self.subTest(response=response),self.assertRaises(m.Refused):
                m.absent(lambda *args:response,m.CID)

    def test_live_all_four_originals_and_engine_before_after(self):
        old,selectors = self.selectors()
        class Call:
            uncertain=False
            def __init__(self): self.calls=[]
            def __call__(self,*args):
                self.calls.append(args)
                return LiveTests().absent_response(args[-1])
        call=Call()
        with patch.object(old,'engine',side_effect=lambda call:call.calls.append(('engine',))):
            observed=m.live_originals(call)
        self.assertEqual(call.calls,[('engine',)]+[('container','inspect',s) for s in selectors]+[('engine',)])
        observed.consume()
        with self.assertRaises(old.DiagnosticUnavailable):observed.consume()

    def test_sticky_cli_uncertainty_refuses_live_capability(self):
        old,_=self.selectors()
        class Call:
            uncertain=True
            def __call__(self,*args):return LiveTests().absent_response(args[-1])
        with patch.object(old,'engine'),self.assertRaises(m.Refused):m.live_originals(Call())


class BindingTests(unittest.TestCase):
    def test_context_reconstruction_changed_rows_refuse(self):
        self.context_replay(changed_rows=True)

    def test_context_changed_actual_bytes_refuse(self):
        self.context_replay(changed_rows=False)

    def context_replay(self,changed_rows):
        from infra import evidence_interpreter_build as build
        from infra import evidence_native_refresh as preparation
        from infra import live_recovery_drill
        refresh,*_=m.modules()
        correct=b'expected'; files={'patched/member.c':correct}
        row={'bytes':len(correct),'sha256':m.digest(correct)}
        value={'context':m.STAGE+'/ctx-interpreter-'+'1'*32,
               'context_files':{'patched/member.c':row}}
        if changed_rows:value['context_files']['patched/member.c']={'bytes':1,'sha256':'0'*64}
        class Pins:
            def enter_context(self,manager):return manager.__enter__()
        class API:
            def pin(self,path,**kwargs):
                raw=b'corrupted' if 'ctx-interpreter-' in str(path) else b'input'
                return nullcontext(io.BytesIO(raw))
        # Source input bytes are supplied to a pure fake reconstruction; actual
        # context reads still pass through the real hash-verifying pin helper.
        original=refresh.pin_bytes
        def read(root,pins,api,name,**kwargs):
            if 'ctx-interpreter-' in name:return original(root,pins,api,name,**kwargs)
            return b'input'
        with patch.object(build,'source_build_inputs',return_value=SimpleNamespace(files=files)),\
             patch.object(refresh,'pin_bytes',side_effect=read),\
             patch.object(live_recovery_drill.PrivateDirectory,'pin',return_value=nullcontext()),\
             patch.object(preparation.Reader,'parents'),self.assertRaises((m.Refused,refresh.RefreshUnavailable)):
            m.revalidate_context(API(),Pins(),value)

    def build(self):
        value=json.loads(Path('ai/state/private-scanner-compile-engine-readback-pcre-aa845a31d7e0466392defe3718a67cee.json').read_text(encoding='utf-8'))
        value['context']=m.STAGE+'/ctx-interpreter-'+'1'*32
        value['context_files']['patched/libclamav/bytecode.c']={'bytes':129358,'sha256':'0'*64}
        return value

    def image(self,build):
        image='sha256:'+'a'*64
        return {'Id':image,'Os':'linux','Architecture':'amd64',
            'Descriptor':{'digest':image,'mediaType':'application/vnd.docker.distribution.manifest.v2+json',
                          'size':3000,'annotations':{'config.digest':build['iidfile']}},
            'RepoTags':[build['tag']], 'Config':{'Labels':{
                'org.kapit.owner':'kapit-public-strict-build-v1','org.kapit.reservation':build['reservation'],
                'org.opencontainers.image.source':'https://github.com/rust-lang/docker-rust'}},
            'RootFS':{'Type':'layers','Layers':['sha256:'+'b'*64]}}

    def test_exact_build_schema(self):
        m.validate_build(self.build())
        value=self.build();value['context']=value['context'].replace('/','\\')
        m.validate_build(value)

    def test_each_cleanup_and_execution_denial(self):
        for key,value in (('compiler_success',False),('exit',True),('reason','INTERRUPTED'),
            ('cleanup_uncertain',True),('cli_reaped',False),('threads_joined',False),
            ('streams_closed',False),('iidfile_status','MISSING'),('iidfile','sha256:bad')):
            build=self.build();build[key]=value
            with self.subTest(key=key),self.assertRaises(m.Refused):m.validate_build(build)

    def test_old_or_escaping_context_refuses(self):
        for context in (m.STAGE+'/ctx6',m.STAGE+'/../ctx-interpreter-'+'1'*32,
                        m.STAGE+'/ctx-interpreter-'+'A'*32):
            build=self.build();build['context']=context
            with self.assertRaises(m.Refused):m.validate_build(build)

    def test_ninth_overlay_required(self):
        build=self.build();del build['context_files']['patched/libclamav/bytecode.c']
        with self.assertRaises(m.Refused):m.validate_build(build)

    def test_manifest_and_config_bound_separately(self):
        build=self.build();doc=self.image(build)
        call=lambda *args:(0,json.dumps([doc]).encode(),b'','EXIT')
        self.assertEqual(m.inspect_image(call,build),doc)
        doc['Descriptor']['annotations']['config.digest']=doc['Id']
        with self.assertRaises(m.Refused):m.inspect_image(call,build)

    def test_tag_label_platform_descriptor_and_rootfs_refusals(self):
        build=self.build()
        for mutate in (lambda d:d.update(RepoTags=[]),lambda d:d.update(Architecture='arm64'),
                       lambda d:d['Config']['Labels'].update(extra='x'),
                       lambda d:d['Descriptor'].update(size=True),
                       lambda d:d.update(RootFS={'Type':'layers','Layers':['bad']})):
            doc=self.image(build);mutate(doc)
            with self.assertRaises(m.Refused):
                m.inspect_image(lambda *args:(0,json.dumps([doc]).encode(),b'','EXIT'),build)

    def test_export_is_exact_ten_public_artifacts(self):
        self.assertEqual(len(m.EXPORT_PATHS),10)
        self.assertEqual(len(set(m.EXPORT_PATHS)),10)
        self.assertIn('/usr/include/pcre2.h',m.EXPORT_PATHS)
        self.assertNotIn('/signatures/daily.cvd',m.EXPORT_PATHS)


class LifecycleTests(unittest.TestCase):
    def test_other_working_directory_refuses_before_protected_pins(self):
        with patch.object(m.Path,'cwd',return_value=m.ROOT.parent),self.assertRaises(m.Refused):
            with m.checked_inputs():raise AssertionError('must not yield')

    def test_receipt_close_failure_overrides_success(self):
        refresh,*_=m.modules();saved=[]
        class Receipt:
            def __init__(self,*args):self.stream=SimpleNamespace(closed=False);self.closes=0
            def save(self,value):saved.append(dict(value))
            def close(self):
                self.closes+=1
                if self.closes == 1:raise OSError('close failure')
                self.stream.closed=True
        @contextmanager
        def inputs():yield None,None,None,None
        with patch.object(refresh,'Receipt',Receipt),patch.object(m,'checked_inputs',inputs),\
             patch.object(m,'build_stage'),self.assertRaises(m.Refused):m.execute('build')
        self.assertFalse(saved[-1]['completed'])
        self.assertEqual(saved[-1]['failure_code'],'RECEIPT_CLOSE_UNCONFIRMED')

    def test_both_live_capabilities_consumed_after_queries_before_build(self):
        self.build_sequence(False)

    def test_expired_builder_capability_prevents_driver(self):
        self.build_sequence(True)

    def build_sequence(self, expired):
        refresh,old,_,_=m.modules(); events=[]
        class Original:
            def consume(self):events.append('original-consume')
        class Builder:
            result={'engine_sha256':old.ENGINE}
            def consume(self):
                events.append('builder-consume')
                if expired:raise m.Refused('STALE')
        @contextmanager
        def observe():
            events.append('builder-observe')
            try:yield Builder()
            finally:events.append('builder-close')
        def execute(code,namespace):
            events.append('driver')
            namespace['receipt']=m.ROOT/'ai/state'/('private-scanner-interpreter-compile-'+'3'*32+'.json')
        def originals(call):events.append('old-live');return Original()
        resume={'live_postflight_module':lambda *args:{'observe':observe}}
        build=BindingTests().build()
        with patch.object(m,'load_fixed',return_value=resume),\
             patch.object(m,'live_originals',side_effect=originals),\
             patch.object(m,'exec',execute,create=True),patch.object(m,'revalidate_context'),\
             patch.object(refresh,'pin_bytes',return_value=json.dumps(build).encode()):
            args=(None,None,None,{m.DRIVER:Path(m.DRIVER).read_bytes(),
                'ai/state/private-scanner-resume-pcre.py':b'fake'}, {})
            if expired:
                with self.assertRaises(m.Refused):m.build_stage(*args)
                self.assertNotIn('driver',events)
            else:
                m.build_stage(*args)
                self.assertEqual(events[:5],['builder-observe','old-live','original-consume','builder-consume','driver'])
                self.assertLess(events.index('driver'),events.index('builder-close'))

    def test_unknown_stage_cannot_reserve_receipt(self):
        refresh,*_=m.modules()
        with patch.object(refresh,'Receipt',side_effect=AssertionError),self.assertRaises(m.Refused):
            m.execute('retry')

    def test_exclusive_receipt_refusal_before_protected_input(self):
        refresh,*_=m.modules()
        with patch.object(refresh,'Receipt',side_effect=FileExistsError),\
             patch.object(m,'checked_inputs',side_effect=AssertionError),\
             self.assertRaises(FileExistsError):m.execute('build')

    def test_input_close_failure_overrides_stage_success(self):
        refresh,*_=m.modules()
        class Receipt:
            def __init__(self,*args):self.saved=None
            def save(self,value):self.saved=dict(value);saved.append(self.saved)
            def close(self):pass
        @contextmanager
        def inputs():
            yield None,None,None,None
            raise RuntimeError('close failure')
        saved=[]
        with patch.object(refresh,'Receipt',Receipt),patch.object(m,'checked_inputs',inputs),\
             patch.object(m,'build_stage'),self.assertRaises(m.Refused):m.execute('build')
        self.assertFalse(saved[-1]['completed'])
        self.assertFalse(saved[-1]['pins_closed'])
        self.assertFalse(saved[-1]['native_eligible'])

    def test_final_deadline_overrides_stage_success(self):
        refresh,*_=m.modules()
        saved=[]
        class Receipt:
            def __init__(self,*args):pass
            def save(self,value):saved.append(dict(value))
            def close(self):pass
        @contextmanager
        def inputs():yield None,None,None,None
        with patch.object(refresh,'Receipt',Receipt),patch.object(m,'checked_inputs',inputs),\
             patch.object(m,'build_stage'),patch.object(m.time,'monotonic',side_effect=[0,1201,1202]),\
             self.assertRaises(m.Refused):m.execute('build')
        self.assertFalse(saved[-1]['completed'])


if __name__ == '__main__':unittest.main()
