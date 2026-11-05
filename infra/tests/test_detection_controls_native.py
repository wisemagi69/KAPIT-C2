"""Mock ownership/process/pipe/thread tests; no actual child or native calls."""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
from io import BytesIO
from itertools import product
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from infra import evidence_detection_controls_native as n
from infra import evidence_native_runtime as runtime
from infra import evidence_rmdir_diagnostic as mechanics
from infra import evidence_rmdir_profile as profile
from infra.test_evidence_native_runtime import inspection
from infra.tests.test_rmdir_native import Journal
from infra.tests.test_detection_controls import document, encode

CID='e'*64
TOKEN='d'*32


def binding():
    return SimpleNamespace(image_id=n.IMAGE, signature_generation=n.GENERATION,
        profile_sha256=n.PROFILE_SHA256, preparation_sha256=n.PREPARATION_SHA256,
        native_sha256=hashlib.sha256(Path(n.__file__).read_bytes()).hexdigest(), controller_sha256='a'*64,
        provenance_sha256='b'*64, parser_sha256=n.PARSER_SHA256, probe_sha256=n.PROBE_SHA256,
        consumed_receipt_sha256=n.CONSUMED_RECEIPT_SHA256, contract=n.CONTRACT)


class Context:
    def __init__(self):
        self.binding=binding();self.stage='diagnostic';self.call_uncertain=False;self.events=[]
        self.profile=Path('C:/fixed/profile');self.docker=Path('C:/fixed/docker');self.config=Path('C:/fixed/config')
        self.command=Mock(side_effect=lambda *a: self.events.append('create') or (0,CID.encode(),b'','EXIT'))
        self.cleanup_command=Mock()
        for name in ('before_phase','consume_before_create','retain_original','record_original','attach_started'):
            setattr(self,name,Mock(side_effect=lambda *a,key=name:self.events.append(key)))
        self.attach_finalized=Mock(side_effect=lambda value:self.events.append(('attach_finalized',value)))
        self.attach_timeout=Mock(return_value=180)
        self.finish_phase=Mock(return_value=True)


class NativeTests(unittest.TestCase):
    def harness(self, context, failure=None, cleanup=None, attach=None):
        probe=n._probe(TOKEN,n.PHASE_ID,context.binding)
        journal=Journal(context.events,failure)
        @contextmanager
        def reserve(*a):yield journal
        value=inspection(probe.phase,exit_code=0)
        value['Name']='/'+probe.name;value['Config'].update(Labels=probe.labels,Cmd=probe.command)
        value['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode()
        stack=self.enterContext(ExitStack())
        for obj,key,replacement in ((n,'_probe',Mock(return_value=probe)),(n,'_reserve',reserve),
                (n,'_check_context',Mock()),(runtime,'_require_cgroup_v2',Mock()),
                (mechanics,'inspect',Mock(return_value=value)),
                (n,'_attach',Mock(return_value=(0,encode(document())),side_effect=attach)),
                (mechanics,'cleanup',Mock(return_value='ORIGINAL_ID_ABSENT_VERIFIED',side_effect=cleanup))):
            stack.enter_context(patch.object(obj,key,replacement))
        return journal

    def test_metadata_fixed_new_namespace_sources_and_no_authority(self):
        value=n.metadata(TOKEN,n.PHASE_ID,binding())
        self.assertEqual(value['expected_name'],'kapit-detection-controls-public-'+TOKEN)
        self.assertEqual(value['expected_labels']['org.kapit.owner'],'kapit-public-detection-controls-v1')
        self.assertEqual(value['source_sha256'],n.PROBE_SHA256)
        for key in ('native','controller','provenance','parser','probe','consumed_receipt'):
            self.assertEqual(value[key+'_sha256'],value['expected_labels']['org.kapit.'+key])
        self.assertFalse(value['native_eligible']);self.assertFalse(value['private_input_allowed'])

    def test_each_invalid_binding_and_phase_refuses(self):
        for key in vars(binding()):
            b=binding();setattr(b,key,'PRIVATE_CANARY')
            with self.assertRaises(Exception):n.metadata(TOKEN,n.PHASE_ID,b)
        for token,phase in ((True,n.PHASE_ID),('a'*31,n.PHASE_ID),(TOKEN,'other')):
            with self.assertRaises(Exception):n.metadata(token,phase,binding())

    def test_fixed_program_and_all_container_bounds(self):
        probe=n._probe(TOKEN,n.PHASE_ID,binding());args=n.create_args(probe,Path('C:/fixed/profile'))
        self.assertEqual(probe.command[:3],['-I','-B','-c'])
        self.assertIn(n.PROBE_SHA256,probe.command[3])
        self.assertEqual(args[-5:],[n.IMAGE,*probe.command])
        self.assertEqual(args[args.index('--memory')+1],str(4*1024**3))
        self.assertEqual(args[args.index('--name')+1],probe.name)

    def test_program_changed_or_oversize_refuses(self):
        for raw in (b'PRIVATE_CANARY',b'x'*262145):
            with patch.object(Path,'open',return_value=BytesIO(raw)),self.assertRaises(n.NativeUnavailable):n._program()

    def test_all27_category_triples_and_exit_types(self):
        for triple in product(('CLEAN','NOT_CLEAN','ERROR'),repeat=3):
            if 'ERROR' in triple:
                with self.assertRaises(n.NativeUnavailable):n._payload(encode(document(triple)),0)
            else:
                result=n._payload(encode(document(triple)),0)
                self.assertEqual([r['category'] for r in result['controls']],list(triple))
        for code in (False,True,1,2,None,0.0):
            with self.assertRaises(n.NativeUnavailable):n._payload(encode(document()),code)

    def test_closed_details_and_comparison_cannot_be_forged(self):
        good=n._payload(encode(document()),0)
        for change in ({'comparison':'PRIVATE_CANARY'},{'raw':'PRIVATE_CANARY'},{'controls':[]}):
            with self.assertRaises(Exception):n._details(dict(good,**change))

    def test_sealed_context_required(self):
        with self.assertRaises(Exception):n._check_context(SimpleNamespace(stage='diagnostic',binding=binding()))

    def test_durable_ownership_order_and_success(self):
        ctx=Context();journal=self.harness(ctx);out=n._phase(ctx)
        self.assertTrue(out['observed']);self.assertTrue(journal.closed)
        self.assertEqual(ctx.events[:8],['before_phase','attempt','consume_before_create','create',
            'retain_original','journal-original','record_original','attach_started'])
        self.assertEqual(ctx.events.count('create'),1)

    def test_attempt_failure_never_creates(self):
        ctx=Context();self.harness(ctx,failure='attempt')
        with self.assertRaises(Exception):n._phase(ctx)
        ctx.command.assert_not_called();ctx.consume_before_create.assert_not_called()

    def test_both_original_write_failures_forbid_start_and_cleanup_original(self):
        for where in ('journal','parent'):
            ctx=Context();self.harness(ctx,failure='record' if where=='journal' else None)
            if where=='parent':ctx.record_original.side_effect=RuntimeError('PRIVATE_CANARY')
            with self.assertRaises(Exception):n._phase(ctx)
            n._attach.assert_not_called();mechanics.cleanup.assert_called_once()
            self.assertEqual(mechanics.cleanup.call_args.args[2],CID)

    def test_parseable_failed_create_retains_original_no_start(self):
        ctx=Context();self.harness(ctx);ctx.command.side_effect=None
        ctx.command.return_value=(1,CID.encode(),b'error','EXIT')
        with self.assertRaises(Exception):n._phase(ctx)
        ctx.retain_original.assert_called_once();n._attach.assert_not_called()
        self.assertEqual(mechanics.cleanup.call_args.args[2],CID)

    def test_unparseable_create_never_adopts_name(self):
        ctx=Context();self.harness(ctx);ctx.command.side_effect=None
        ctx.command.return_value=(0,b'invalid',b'','EXIT')
        with self.assertRaises(Exception):n._phase(ctx)
        n._attach.assert_not_called();ctx.retain_original.assert_not_called()
        self.assertIsNone(mechanics.cleanup.call_args.args[2])

    def test_attach_and_cleanup_faults_refuse_sticky(self):
        for where in ('attach','cleanup','finish','journal','uncertainty'):
            ctx=Context();self.harness(ctx,attach=RuntimeError('PRIVATE_CANARY') if where=='attach' else None,
                cleanup=RuntimeError('PRIVATE_CANARY') if where=='cleanup' else None,
                failure='finish' if where=='journal' else None)
            if where=='finish':ctx.finish_phase.side_effect=RuntimeError('PRIVATE_CANARY')
            if where=='uncertainty':ctx.call_uncertain=True
            with self.assertRaises(n.NativeUnavailable):n._phase(ctx)
            self.assertEqual(ctx.events.count('create'),1)

    def test_wrong_finalizer_return_type_refuses(self):
        ctx=Context();self.harness(ctx);ctx.finish_phase.return_value=None
        with self.assertRaises(n.NativeUnavailable):n._phase(ctx)


class FakeThread:
    instances=[]
    late=False
    stuck=False
    def __init__(self,target,args,daemon):
        self.target,self.args=target,args;self.ran=False;self.instances.append(self)
    def start(self):
        if not self.late:self.target(*self.args);self.ran=True
    def join(self,timeout):
        if self.late and not self.ran:self.target(*self.args);self.ran=True
    def is_alive(self):return self.stuck


class AttachTests(unittest.TestCase):
    def run_attach(self,stdout=b'{}',stderr=b'',late=False,process=None,clock=None):
        process=process or SimpleNamespace(stdin=BytesIO(),stdout=BytesIO(stdout),stderr=BytesIO(stderr),
            wait=Mock(return_value=0),kill=Mock())
        FakeThread.instances=[]
        with patch.object(n.subprocess,'Popen',return_value=process) as popen, \
                patch.object(n.threading,'Thread',FakeThread),patch.object(FakeThread,'late',late), \
                patch.object(n.time,'monotonic',side_effect=clock or (lambda:0)):
            result=n._attach(['fixed-owned-cli'],timeout=180)
        return result,process,popen

    def test_success_held_empty_stdin_exact_owned_reap_pipe_thread_closure(self):
        result,process,popen=self.run_attach()
        self.assertEqual(result,(0,b'{}'));process.kill.assert_not_called()
        self.assertTrue(all(stream.closed for stream in (process.stdin,process.stdout,process.stderr)))
        self.assertEqual(len(FakeThread.instances),2)
        self.assertTrue(all(t.ran for t in FakeThread.instances));self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertEqual(popen.call_args.kwargs['bufsize'],0)
        self.assertTrue(popen.call_args.kwargs['close_fds'])
        self.assertLessEqual(set(popen.call_args.kwargs['env']),{'SYSTEMROOT','WINDIR','TEMP','TMP'})

    def test_exact_output_and_discard_boundaries(self):
        result,_,_=self.run_attach(b'x'*4096,b'PRIVATE_CANARY'+b'y'*(16384-14))
        self.assertEqual(len(result[1]),4096)
        for stdout,stderr in ((b'x'*4097,b''),(b'',b'y'*16385)):
            with self.assertRaises(n.NativeUnavailable):self.run_attach(stdout,stderr)

    def test_late_stdout_stderr_overflow_after_wait_refuses(self):
        for stdout,stderr in ((b'x'*4097,b''),(b'',b'y'*16385)):
            with self.assertRaises(n.NativeUnavailable):self.run_attach(stdout,stderr,late=True)

    def test_timeout_kills_reaps_owned_process_and_closes(self):
        process=SimpleNamespace(stdin=BytesIO(),stdout=BytesIO(),stderr=BytesIO(),wait=Mock(return_value=0),kill=Mock())
        with self.assertRaises(n.NativeUnavailable):self.run_attach(process=process,clock=iter([0,181]).__next__)
        process.kill.assert_called_once();process.wait.assert_called_once_with(timeout=5)
        self.assertTrue(process.stdin.closed)

    def test_abnormal_exit_and_wait_failure_refuse(self):
        for code in (False,1,-9):
            process=SimpleNamespace(stdin=BytesIO(),stdout=BytesIO(),stderr=BytesIO(),wait=Mock(return_value=code),kill=Mock())
            with self.assertRaises(n.NativeUnavailable):self.run_attach(process=process)
        process=SimpleNamespace(stdin=BytesIO(),stdout=BytesIO(),stderr=BytesIO(),
            wait=Mock(side_effect=[RuntimeError('PRIVATE_CANARY'),0]),kill=Mock())
        with self.assertRaises(n.NativeUnavailable):self.run_attach(process=process)
        process.kill.assert_called_once()

    def test_late_wait_or_drain_completion_cannot_pass_deadline(self):
        now=[0]
        def late_wait(**kwargs):now[0]=181;return 0
        process=SimpleNamespace(stdin=BytesIO(),stdout=BytesIO(),stderr=BytesIO(),
            wait=Mock(side_effect=late_wait),kill=Mock())
        with self.assertRaises(n.NativeUnavailable):self.run_attach(process=process,clock=lambda:now[0])
        now[0]=0
        def late_join(thread,timeout):now[0]=181
        with patch.object(FakeThread,'join',late_join),self.assertRaises(n.NativeUnavailable):
            self.run_attach(clock=lambda:now[0])

    def test_reader_failure_or_nonbytes_refuses(self):
        for result in (None,'PRIVATE_CANARY',RuntimeError('PRIVATE_CANARY')):
            stream=Mock();stream.read.side_effect=result if isinstance(result,Exception) else None
            if not isinstance(result,Exception):stream.read.return_value=result
            stream.closed=True
            process=SimpleNamespace(stdin=BytesIO(),stdout=stream,stderr=BytesIO(),wait=Mock(return_value=0),kill=Mock())
            with self.assertRaises(n.NativeUnavailable):self.run_attach(process=process)

    def test_join_and_pipe_close_failures_are_sticky(self):
        with patch.object(FakeThread,'stuck',True),self.assertRaises(n.NativeUnavailable):self.run_attach()
        process=SimpleNamespace(stdin=BytesIO(),stdout=BytesIO(),stderr=BytesIO(),wait=Mock(return_value=0),kill=Mock())
        process.stdin=Mock(closed=False);process.stdin.close.side_effect=RuntimeError('PRIVATE_CANARY')
        with self.assertRaises(n.NativeUnavailable):self.run_attach(process=process)

    def test_invalid_timeouts_do_not_launch(self):
        for value in (True,0,181,float('nan')):
            with patch.object(n.subprocess,'Popen') as popen,self.assertRaises(n.NativeUnavailable):n._attach(['fixed'],timeout=value)
            popen.assert_not_called()


if __name__=='__main__':unittest.main()
