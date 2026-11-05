"""Fake filesystem/ACL host only: no Windows API, Docker or real journal files."""
from contextlib import contextmanager
from copy import deepcopy
import io
import json
import unittest
from unittest.mock import Mock, patch

from infra import evidence_native_ownership as ownership


CID='d'*64


def arguments(*,probe=False,strict=False,pcre=False):
    token='a'*32; mode='scan'; scenario='pcre' if pcre else 'strict' if strict else 'confinement'
    labels={'org.kapit.owner':'kapit-same-image-public-probe-v1' if probe else 'kapit-public-native-fixture-v1',
            'org.kapit.run':token,'org.kapit.reservation':token,'org.kapit.purpose':'same-image-public-only' if probe else 'public-native-fixtures-only',
            'org.kapit.mode':mode,'org.kapit.policy':ownership.POLICY}
    if probe:labels.update({'org.kapit.scenario':scenario,'org.kapit.probe':ownership.PCRE_PROBE if pcre else ownership.STRICT_PROBE if strict else ownership.PUBLIC_PROBE})
    return {'token':token,'image_id':'sha256:'+'b'*64,'signature_generation':'c'*64,'purpose':'same-image-probe' if probe else 'native-fixture',
            'mode':mode,'scenario':scenario if probe else 'png_clean','phase':'probe' if probe else 'original_scan',
            'source_policy':ownership.POLICY,'expected_labels':labels}


class FakeHost:
    def __init__(self):self.saved={};self.events=[];self.fail=None;self.close_failure=False;self.closed=False
    def __enter__(self):self.events.append('protected-fresh-child');return self
    def save(self,name,doc):
        self.events.append(name)
        if self.fail==name:raise OSError('never expose backend diagnostic')
        if name in self.saved:raise FileExistsError('no overwrite')
        self.saved[name]=json.loads(ownership._canonical(doc))
    def close(self):
        self.events.append('close-all-pins');self.closed=True
        if self.close_failure:raise OSError('release failure')


class OwnershipTests(unittest.TestCase):
    def test_previous_pre_readback_pcre_source_label_is_not_current_identity(self):
        kwargs=arguments(probe=True,pcre=True)
        kwargs['expected_labels']['org.kapit.probe']='423d0249f3d49555e5695b13c050702a91e6dbf30cf367f90f229746a0221b29'
        with self.assertRaises(ownership.OwnershipUnavailable):ownership._metadata(**kwargs)

    def test_one_fixed_pcre_probe_identity_scan_mode_only(self):
        kwargs=arguments(probe=True,pcre=True)
        self.assertEqual(ownership._metadata(**kwargs)['expected_labels']['org.kapit.probe'],ownership.PCRE_PROBE)
        for variant in ('decode','wronghash','rawlabel'):
            changed=deepcopy(kwargs)
            if variant=='decode':changed['mode']='decode';changed['expected_labels']['org.kapit.mode']='decode'
            elif variant=='wronghash':changed['expected_labels']['org.kapit.probe']='f'*64
            else:changed['expected_labels']['arbitrary']='caller signature'
            with self.assertRaises(ownership.OwnershipUnavailable):ownership._metadata(**changed)
    def test_durable_metadata_attempt_original_terminal_order_and_no_native_proof(self):
        host=FakeHost()
        with patch.object(ownership,'_Host',return_value=host):
            with ownership.reserve(**arguments()) as journal:
                self.assertEqual(host.events,['protected-fresh-child','reservation.json'])
                journal.mark_create_attempted();journal.record_original(CID)
                self.assertTrue(journal.recorded)
                self.assertEqual(host.saved['ownership.json']['original_id'],CID)
                journal.finish('ORIGINAL_ID_ABSENT_VERIFIED')
        self.assertEqual(host.events,['protected-fresh-child','reservation.json','create-attempt.json','ownership.json','result.json','close-all-pins'])
        self.assertFalse(host.saved['result.json']['native_eligible']);self.assertTrue(host.closed)

    def test_closed_fixed_software_metadata_and_label_families(self):
        for kwargs in [arguments(),arguments(probe=True),arguments(probe=True,strict=True)]:
            metadata=ownership._metadata(**kwargs)
            self.assertEqual(set(metadata),{'schema','token','image_id','signature_generation','purpose','mode','scenario','phase','source_policy','expected_name','expected_labels','native_eligible'})
            self.assertFalse(metadata['native_eligible'])
        cases=[]
        for key,value in [('token','../path'),('image_id','sha256:'+'0'*64),('signature_generation','0'*64),('scenario','caller-supplied'),('source_policy','e'*64),('phase','arbitrary'),('mode','decode')]:
            kwargs=arguments();kwargs[key]=value;cases.append(kwargs)
        for key in ['raw','user_id','photo_sha256','secret']:
            kwargs=arguments();kwargs['expected_labels'][key]='not permitted';cases.append(kwargs)
        kwargs=arguments();kwargs['expected_labels']['org.kapit.reservation']='f'*32;cases.append(kwargs)
        kwargs=arguments(probe=True,strict=True);kwargs['mode']='decode';kwargs['expected_labels']['org.kapit.mode']='decode';cases.append(kwargs)
        for kwargs in cases:
            with patch.object(ownership,'_Host',side_effect=AssertionError('must reject before host')):
                with self.assertRaises(ownership.OwnershipUnavailable):
                    with ownership.reserve(**kwargs):pass

    def test_never_created_and_unknown_id_absence_are_distinct(self):
        for attempted,status in [(False,'NOT_CREATED'),(True,'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED')]:
            host=FakeHost()
            with patch.object(ownership,'_Host',return_value=host):
                with ownership.reserve(**arguments()) as journal:
                    if attempted:journal.mark_create_attempted()
                    journal.finish(status)
            self.assertEqual(host.saved['result.json']['ownership_status'],status)
            self.assertIsNone(host.saved['result.json']['original_id'])

    def test_single_assignment_and_required_attempt_cannot_be_repeated_or_conflicted(self):
        for variant in ('no-attempt','repeat-attempt','repeat-id','conflict-id','bad-id'):
            host=FakeHost()
            with patch.object(ownership,'_Host',return_value=host),self.assertRaises(ownership.OwnershipUnavailable):
                with ownership.reserve(**arguments()) as journal:
                    if variant!='no-attempt':journal.mark_create_attempted()
                    if variant=='repeat-attempt':journal.mark_create_attempted()
                    journal.record_original('bad' if variant=='bad-id' else CID)
                    journal.record_original(CID if variant=='repeat-id' else 'e'*64)
            self.assertTrue(host.closed)
            self.assertEqual(host.saved['result.json']['ownership_status'],'CLEANUP_UNCONFIRMED')

    def test_inconsistent_terminal_statuses_never_success(self):
        for attempted,recorded,status in [(False,False,'ORIGINAL_ID_ABSENT_VERIFIED'),(False,False,'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED'),
                                         (True,False,'NOT_CREATED'),(True,True,'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED')]:
            host=FakeHost()
            with patch.object(ownership,'_Host',return_value=host),self.assertRaises(ownership.OwnershipUnavailable):
                with ownership.reserve(**arguments()) as journal:
                    if attempted:journal.mark_create_attempted()
                    if recorded:journal.record_original(CID)
                    journal.finish(status)
            self.assertEqual(host.saved['result.json']['ownership_status'],'CLEANUP_UNCONFIRMED');self.assertTrue(host.closed)

    def test_missing_finish_or_keyboard_interrupt_still_persists_uncertainty_and_closes(self):
        for interrupt in (False,True):
            host=FakeHost()
            with patch.object(ownership,'_Host',return_value=host),self.assertRaises(ownership.OwnershipUnavailable):
                with ownership.reserve(**arguments()) as journal:
                    journal.mark_create_attempted()
                    if interrupt:raise KeyboardInterrupt()
            self.assertTrue(host.closed);self.assertEqual(host.saved['result.json']['ownership_status'],'CLEANUP_UNCONFIRMED')

    def test_record_write_failures_cannot_return_durable_capability(self):
        for stage in ('reservation.json','create-attempt.json','ownership.json'):
            host=FakeHost();host.fail=stage;inspected=False
            with patch.object(ownership,'_Host',return_value=host),self.assertRaises(ownership.OwnershipUnavailable):
                with ownership.reserve(**arguments()) as journal:
                    journal.mark_create_attempted();journal.record_original(CID)
                    inspected=True
            self.assertFalse(inspected);self.assertTrue(host.closed)
            self.assertEqual(host.saved['result.json']['ownership_status'],'CLEANUP_UNCONFIRMED')

    def test_finish_write_or_pin_release_failure_dominates_observed_absence(self):
        for stage in ('result.json','release'):
            host=FakeHost();host.fail=stage;host.close_failure=stage=='release'
            with patch.object(ownership,'_Host',return_value=host),self.assertRaises(ownership.OwnershipUnavailable) as error:
                with ownership.reserve(**arguments()) as journal:
                    journal.mark_create_attempted();journal.record_original(CID);journal.finish('ORIGINAL_ID_ABSENT_VERIFIED')
            self.assertTrue(host.closed);self.assertEqual(error.exception.code,'OWNERSHIP_CLEANUP_UNCONFIRMED')

    def test_actual_host_save_fake_files_fsync_acl_then_held_read_pin(self):
        events=[];data={};protected=set()
        class File:
            def __init__(self,name):self.name=name
            @contextmanager
            def open(self,mode):
                events.append(mode)
                if mode=='xb':
                    if self.name in data:raise FileExistsError()
                    data[self.name]=b'';yield io.BytesIO()
                else:
                    outer=self
                    class Writer:
                        def write(self,raw):
                            self_test.assertIn(outer.name,protected);events.append('write');data[outer.name]=raw
                        def flush(self):events.append('flush')
                        def fileno(self):return 77
                    yield Writer()
        class Directory:
            def __truediv__(self,name):return File(name)
        class API:
            def protect(self,path):events.append('protect');protected.add(path.name)
            @contextmanager
            def pin(self,path,*,private=False):
                self_test.assertTrue(private);events.append('pin-readback')
                try:yield io.BytesIO(data[path.name])
                finally:events.append('pin-released')
        self_test=self;host=ownership._Host('a'*32);host.path=Directory();host.api=API()
        with patch.object(ownership.os,'fsync',side_effect=lambda fd:events.append('fsync')):
            host.save('ownership.json',{'schema':1})
        self.assertEqual(events,['xb','protect','r+b','write','flush','fsync','pin-readback'])
        host.close();self.assertEqual(events[-1],'pin-released')

    def test_host_refuses_unprotected_parent_or_existing_child_before_save(self):
        from infra import evidence_tools,live_recovery_drill
        for failure in ('stage','create'):
            events=[]
            class API:
                @contextmanager
                def pin(self,path,**kwargs):
                    events.append(('ancestor',str(path)))
                    try:yield None
                    finally:events.append(('released',str(path)))
            class Private:
                @contextmanager
                def pin(self,path,**kwargs):
                    if failure=='stage':raise OSError('bad ACL')
                    yield None
                def create(self,path):events.append(('create',str(path)));raise FileExistsError('never adopt')
            with patch.object(ownership.os,'name','nt'),patch.object(evidence_tools,'Windows',API),patch.object(evidence_tools,'checked',side_effect=lambda path:path),patch.object(live_recovery_drill,'PrivateDirectory',Private):
                host=ownership._Host('a'*32)
                with self.assertRaises(OSError):host.__enter__()
            self.assertEqual(sum(event[0]=='create' for event in events),0 if failure=='stage' else 1)
            self.assertEqual(sum(event[0]=='ancestor' for event in events),sum(event[0]=='released' for event in events))

    def test_every_owned_pin_release_attempted_even_if_one_raises(self):
        host=ownership._Host('a'*32);released=[]
        for number in range(4):
            def close(index=number):
                released.append(index)
                if index==2:raise OSError('one close failed')
            host.stack.callback(close)
        with self.assertRaises(OSError):host.close()
        self.assertEqual(released,[3,2,1,0])

    def test_actual_host_acl_fsync_pin_or_readback_failure_never_records_original(self):
        for failure in ('protect','fsync','pin','readback'):
            stored={};events=[]
            class File:
                def __init__(self,name):self.name=name
                @contextmanager
                def open(self,mode):
                    if mode=='xb':
                        if self.name in stored:raise FileExistsError()
                        stored[self.name]=b'';yield io.BytesIO()
                    else:
                        outer=self
                        class Writer:
                            def write(self,raw):stored[outer.name]=raw
                            def flush(self):events.append('flush')
                            def fileno(self):return 7
                        yield Writer()
            class Directory:
                def __truediv__(self,name):return File(name)
            class API:
                def protect(self,path):
                    events.append('protect')
                    if failure=='protect':raise OSError('ACL uncertain')
                @contextmanager
                def pin(self,path,**kwargs):
                    if failure=='pin':raise OSError('pin uncertain')
                    try:yield io.BytesIO(b'wrong' if failure=='readback' else stored[path.name])
                    finally:events.append('released')
            host=ownership._Host('a'*32);host.path=Directory();host.api=API()
            journal=ownership._Journal(host,ownership._metadata(**arguments()));journal.attempted=True
            with patch.object(ownership.os,'fsync',side_effect=OSError('sync uncertain') if failure=='fsync' else None):
                with self.assertRaises(ownership.OwnershipUnavailable):journal.record_original(CID)
            self.assertTrue(journal.failed);self.assertFalse(journal.recorded)
            if failure=='protect':self.assertEqual(stored['ownership.json'],b'')
            host.close()

    def test_terminal_journal_is_single_write_and_cannot_be_reopened(self):
        host=FakeHost()
        with patch.object(ownership,'_Host',return_value=host):
            with ownership.reserve(**arguments()) as journal:journal.finish('NOT_CREATED')
        before=deepcopy(host.saved)
        with self.assertRaises(ownership.OwnershipUnavailable):journal.finish('NOT_CREATED')
        with self.assertRaises(ownership.OwnershipUnavailable):journal.mark_create_attempted()
        self.assertEqual(host.saved,before)


if __name__=='__main__':unittest.main()
