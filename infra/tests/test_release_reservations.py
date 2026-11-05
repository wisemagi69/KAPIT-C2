"""Synthetic ownership faults; no Windows adapter is constructed."""
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from infra import evidence_release_reservations as r

OWNER='S-1-5-21-42'
PAYLOAD={'authorization_sha256':'a'*64,'source_bundle_sha256':'b'*64}
NONCE='c'*32


def facts(directory=False, number=1):
    return dict(volume=2**63+17,file_id=f'{number:032x}',attributes=0x10 if directory else 0x80,
                links=1,size=0,disk=True,private=True,owner=OWNER)


class File:
    def __init__(self, data=b'', *, directory=False, number=1, fault=None):
        self.data=data; self.facts=facts(directory,number); self.facts['size']=len(data)
        self.fault=fault; self.closes=0; self.writes=0; self.events=[]
    def identity(self):
        self.events.append('identity')
        if self.fault=='identity': raise OSError()
        return dict(self.facts)
    def read(self, maximum):
        self.events.append('read')
        if self.fault=='read_raise': raise OSError()
        if self.fault=='read_partial': return self.data[:-1]
        if self.fault=='read_extra': return self.data+b'x'
        if self.fault=='read_replace': self.facts['file_id']='d'*32
        return self.data[:maximum]
    def write(self, payload):
        self.events.append('write'); self.writes+=1
        self.data=payload; self.facts['size']=len(payload)
        if self.fault=='write_partial': self.data=payload[:-1]; self.facts['size']-=1; return len(payload)-1
        if self.fault=='write_bool': return True
        if self.fault=='write_raise': raise OSError()
        if self.fault=='write_replace': self.facts['file_id']='d'*32
        return len(payload)
    def flush(self):
        self.events.append('flush')
        if self.fault=='flush_raise': raise OSError()
        if self.fault=='flush_false': return False
        if self.fault=='callbacks':
            self.close=lambda: (_ for _ in ()).throw(AssertionError('replacement'))
            self.read=lambda maximum: b'forged'
    def close(self):
        self.events.append('close'); self.closes+=1
        if self.fault=='close_raise': raise OSError()
        if self.fault=='close_false': return False


class Provider:
    def __init__(self, records=None, fault=None):
        self.records={} if records is None else records; self.fault=fault; self.parents=[]; self.created=[]
    def pin_parent(self, path):
        obj=File(directory=True,number=len(self.parents)+100)
        if path != 'ai/state/release-reservations-v1': obj.facts['private']=False
        self.parents.append(obj)
        return obj
    def create_new(self, path, payload):
        if path in self.records: raise FileExistsError()
        obj=File(number=99,fault=self.fault); self.records[path]=obj; self.created.append(obj)
        return obj


class IdentityTests(unittest.TestCase):
    def test_full_width_identity(self):
        value=facts(); value['file_id']='f'*32; value['volume']=2**64-1
        self.assertEqual(r.validate_identity(value,owner=OWNER),value)
    def test_closed_identity_fields(self):
        for field in facts():
            with self.subTest(field=field):
                value=facts(); del value[field]
                with self.assertRaises(r.ReservationRefused): r.validate_identity(value,owner=OWNER)
        value=facts(); value['extra']=None
        with self.assertRaises(r.ReservationRefused): r.validate_identity(value,owner=OWNER)
    def test_integer_bool_width_aliases(self):
        for field,values in {'volume':[True,0,2**64,-1], 'links':[True,0,2],
                             'attributes':[True,-1,2**32,0x400,0x40,0x10],
                             'size':[True,-1,1048577]}.items():
            for bad in values:
                with self.subTest(field=field,value=bad):
                    value=facts(); value[field]=bad
                    with self.assertRaises(r.ReservationRefused): r.validate_identity(value,owner=OWNER)
    def test_ids_security_and_owner(self):
        for field,bad in [('file_id','A'*32),('file_id','0'*32),('file_id','1'*31),
                          ('disk',1),('private',1),('owner',OWNER+'1')]:
            with self.subTest(field=field,value=bad):
                value=facts(); value[field]=bad
                with self.assertRaises(r.ReservationRefused): r.validate_identity(value,owner=OWNER)
    def test_existing_nonprivate_allowed_only_when_not_required(self):
        value=facts(); value['private']=False
        r.validate_identity(value,owner=OWNER)
        with self.assertRaises(r.ReservationRefused): r.validate_identity(value,owner=OWNER,require_private=True)
    def test_parent_directory_required(self):
        with self.assertRaises(r.ReservationRefused): r.validate_identity(facts(),owner=OWNER,directory=True)
        r.validate_identity(facts(True),owner=OWNER,directory=True)


class SnapshotTests(unittest.TestCase):
    def test_payload_4096_boundary_and_4097_refuses_before_write(self):
        obj=File(); held=r.capture_owned(obj,owner=OWNER,writable=True)
        held.write_exact(b'x'*4096); held.flush()
        self.assertEqual(held.read_exact(4096),b'x'*4096); held.close()
        obj=File(); held=r.capture_owned(obj,owner=OWNER,writable=True)
        with self.assertRaises(r.ReservationRefused): held.write_exact(b'x'*4097)
        self.assertEqual(obj.writes,0)
        try: held.close()
        except r.ReservationRefused: pass
    def test_candidate_payload_4097_refuses_before_creation(self):
        provider=object.__new__(r.CandidateWin32Provider)
        provider._path=lambda *a: (_ for _ in ()).throw(AssertionError('path accessed'))
        provider._open=lambda *a,**k: (_ for _ in ()).throw(AssertionError('create accessed'))
        with self.assertRaises(r.ReservationRefused):
            provider.create_new('ai/state/release-reservations-v1/'+NONCE+'.reservation',b'x'*4097)
    def test_complete_read_exact_original(self):
        obj=File(b'abc'); held=r.capture_owned(obj,owner=OWNER)
        self.assertEqual(held.read_exact(3),b'abc'); held.close(); self.assertEqual(obj.closes,1)
    def test_partial_extra_raise_and_replacement_refuse(self):
        for fault in ('read_partial','read_extra','read_raise','read_replace'):
            with self.subTest(fault=fault):
                obj=File(b'abc',fault=fault); held=r.capture_owned(obj,owner=OWNER)
                with self.assertRaises(r.ReservationRefused): held.read_exact(3)
                with self.assertRaises(r.ReservationRefused): held.close()
                self.assertEqual(obj.closes,1)
    def test_same_bytes_different_original_refuses(self):
        obj=File(b'abc'); held=r.capture_owned(obj,owner=OWNER); obj.facts['file_id']='e'*32
        with self.assertRaises(r.ReservationRefused): held.read_exact(3)
        with self.assertRaises(r.ReservationRefused): held.close()
    def test_callback_replacement_uses_captured_original(self):
        obj=File(b'abc'); held=r.capture_owned(obj,owner=OWNER)
        obj.identity=lambda: facts(); obj.read=lambda maximum:b'bad'; obj.close=lambda:False
        self.assertEqual(held.read_exact(3),b'abc'); held.close(); self.assertEqual(obj.closes,1)
    def test_failed_capture_closes_original(self):
        obj=File(fault='identity')
        with self.assertRaises(r.ReservationRefused): r.capture_owned(obj,owner=OWNER)
        self.assertEqual(obj.closes,1)
    def test_close_then_raised_is_sticky_and_not_retried(self):
        obj=File(fault='close_raise'); held=r.capture_owned(obj,owner=OWNER)
        for _ in range(2):
            with self.assertRaises(r.ReservationRefused): held.close()
        self.assertEqual(obj.closes,1)
    def test_exported_snapshot_errors_discard_private_exception_context(self):
        for fault,method in [('read_raise','read'),('flush_raise','flush'),('write_raise','write'),('close_raise','close')]:
            with self.subTest(fault=fault):
                obj=File(b'abc' if method=='read' else b'',fault=fault)
                held=r.capture_owned(obj,owner=OWNER,writable=method in ('flush','write'))
                try:
                    if method=='read': held.read_exact(3)
                    elif method=='write': held.write_exact(b'abc')
                    else: getattr(held,method)()
                except r.ReservationRefused as error:
                    self.assertIsNone(error.__context__); self.assertIsNone(error.__cause__)
                else: self.fail('expected refusal')
                try: held.close()
                except r.ReservationRefused: pass


class StoreTests(unittest.TestCase):
    def reserve(self, provider, **kw):
        return r.ProtectedReservationStore(provider,owner=OWNER).reserve(
            kw.get('operation','FRESH_PREFLIGHT'),kw.get('nonce',NONCE),kw.get('payload',PAYLOAD))
    def test_complete_reservation_is_not_authority(self):
        p=Provider(); result=self.reserve(p)
        self.assertFalse(result.production_eligible); self.assertEqual(result.source_bundle_sha256,'b'*64)
        obj=p.created[0]; body=json.loads(obj.data)
        self.assertEqual(body,dict(schema=1,operation='FRESH_PREFLIGHT',nonce=NONCE,**PAYLOAD))
        self.assertEqual(obj.writes,1); self.assertEqual(obj.closes,1)
        self.assertTrue(all(x.closes==1 for x in p.parents))
        self.assertIn('ai/state/release-reservations-v1/'+NONCE+'.reservation',p.records)
    def test_reopen_replay_and_operation_alias_refuse(self):
        p=Provider(); self.reserve(p)
        for operation in ('FRESH_PREFLIGHT','ONE_COMPARISON'):
            with self.assertRaises(r.ReservationRefused): self.reserve(Provider(p.records),operation=operation)
        self.assertEqual(len(p.records),1)
    def test_all_late_failures_consume_original_across_store_instances(self):
        for fault in ('write_partial','write_bool','write_raise','write_replace','flush_raise',
                      'flush_false','read_partial','read_extra','read_raise','read_replace','close_raise','close_false'):
            with self.subTest(fault=fault):
                p=Provider(fault=fault)
                with self.assertRaises(r.ReservationRefused): self.reserve(p)
                self.assertEqual(len(p.records),1); self.assertEqual(p.created[0].closes,1)
                self.assertTrue(all(x.closes==1 for x in p.parents))
                with self.assertRaises(r.ReservationRefused): self.reserve(Provider(p.records))
    def test_invalid_input_never_accesses_provider(self):
        for kw in ({'nonce':'C'*32},{'nonce':'../x'},{'operation':'unknown'},
                   {'payload':dict(PAYLOAD,extra='x')},{'payload':{'authorization_sha256':'a'*64}},
                   {'payload':dict(PAYLOAD,source_bundle_sha256=True)}):
            with self.subTest(kw=kw):
                p=Provider()
                with self.assertRaises(r.ReservationRefused): self.reserve(p,**kw)
                self.assertEqual(p.parents,[]); self.assertEqual(p.records,{})
    def test_hardlink_reparse_and_nonprivate_fresh_original_refuse(self):
        for field,bad in [('links',2),('attributes',0x480),('private',False),('owner','other')]:
            with self.subTest(field=field):
                p=Provider(); create=p.create_new
                def altered(path,payload):
                    obj=create(path,payload); obj.facts[field]=bad; return obj
                p.create_new=altered
                with self.assertRaises(r.ReservationRefused): self.reserve(p)
                self.assertEqual(p.created[0].closes,1); self.assertEqual(len(p.records),1)
    def test_parent_substitution_before_write_retains_empty_original(self):
        p=Provider(); create=p.create_new
        def altered(path,payload):
            obj=create(path,payload); p.parents[1].facts['file_id']='d'*32; return obj
        p.create_new=altered
        with self.assertRaises(r.ReservationRefused): self.reserve(p)
        self.assertEqual(p.created[0].data,b''); self.assertEqual(p.created[0].closes,1)
    def test_parent_close_failure_unwinds_every_parent(self):
        p=Provider(); pin=p.pin_parent
        def altered(path):
            obj=pin(path)
            if path=='ai/state': obj.fault='close_raise'
            return obj
        p.pin_parent=altered
        with self.assertRaises(r.ReservationRefused): self.reserve(p)
        self.assertTrue(all(x.closes==1 for x in p.parents)); self.assertEqual(p.created[0].closes,1)
    def test_late_parent_identity_failure_still_closes_every_original(self):
        p=Provider(); create=p.create_new
        def altered(path,payload):
            obj=create(path,payload); original_close=obj.close
            def close():
                original_close(); p.parents[-1].facts['file_id']='e'*32
            obj.close=close
            return obj
        p.create_new=altered
        with self.assertRaises(r.ReservationRefused): self.reserve(p)
        self.assertTrue(all(x.closes==1 for x in p.parents)); self.assertEqual(p.created[0].closes,1)
    def test_callback_substitution_during_flush_does_not_redirect_readback_or_close(self):
        p=Provider(fault='callbacks'); self.reserve(p); self.assertEqual(p.created[0].closes,1)
    def test_provider_callback_substitution_after_store_construction(self):
        p=Provider(); store=r.ProtectedReservationStore(p,owner=OWNER)
        p.create_new=lambda *a: (_ for _ in ()).throw(AssertionError())
        p.pin_parent=lambda *a: (_ for _ in ()).throw(AssertionError())
        store.reserve('FRESH_PREFLIGHT',NONCE,PAYLOAD); self.assertEqual(len(p.records),1)
    def test_nonempty_create_original_cannot_be_adopted(self):
        p=Provider(); create=p.create_new
        def prefilled(path,payload):
            obj=create(path,payload); obj.data=b'x'; obj.facts['size']=1; return obj
        p.create_new=prefilled
        with self.assertRaises(r.ReservationRefused): self.reserve(p)
        self.assertEqual(p.created[0].writes,0)
    def test_private_namespace_is_required(self):
        p=Provider(); pin=p.pin_parent
        def altered(path):
            obj=pin(path)
            if path.endswith('-v1'): obj.facts['private']=False
            return obj
        p.pin_parent=altered
        with self.assertRaises(r.ReservationRefused): self.reserve(p)
        self.assertEqual(p.created,[])
    def test_aliasing_parent_objects_are_refused_before_creation(self):
        p=Provider(); pin=p.pin_parent
        def alias(path):
            obj=pin(path); obj.facts['file_id']='f'*32; return obj
        p.pin_parent=alias
        with self.assertRaises(r.ReservationRefused): self.reserve(p)
        self.assertEqual(p.created,[]); self.assertTrue(all(x.closes==1 for x in p.parents))
    def test_production_refuses_before_input_or_backend(self):
        class Bomb:
            def __getattribute__(self,name): raise AssertionError()
        with self.assertRaises(r.ReservationRefused): r.production_open(Bomb(), backend=Bomb())


class PortablePersistenceTests(unittest.TestCase):
    """Ordinary fresh tempfiles only: no OS security or crash qualification."""
    class TempFile(File):
        def __init__(self,path,partial=False):
            super().__init__(number=120)
            self.stream=open(path,'x+b',buffering=0); self.partial=partial
        def identity(self):
            self.facts['size']=os.fstat(self.stream.fileno()).st_size
            return super().identity()
        def write(self,payload):
            if self.partial:
                self.stream.write(payload[:3]); raise OSError('synthetic partial write')
            return self.stream.write(payload)
        def read(self,maximum):
            self.stream.seek(0); return self.stream.read(maximum)
        def flush(self):
            self.stream.flush(); os.fsync(self.stream.fileno())
        def close(self):
            self.stream.close(); self.closes+=1
    class TempProvider(Provider):
        def __init__(self,directory,partial=False):
            super().__init__(); self.directory=directory; self.partial=partial
        def create_new(self,path,payload):
            # Fixed validated basename only. Private/identity facts are mocked.
            obj=PortablePersistenceTests.TempFile(os.path.join(self.directory,path.split('/')[-1]),self.partial)
            self.created.append(obj); return obj
    def test_new_instance_refuses_existing_original_after_normal_close(self):
        with tempfile.TemporaryDirectory(prefix='kapit-public-reservation-') as directory:
            p=self.TempProvider(directory)
            r.ProtectedReservationStore(p,owner=OWNER).reserve('FRESH_PREFLIGHT',NONCE,PAYLOAD)
            path=os.path.join(directory,NONCE+'.reservation')
            with open(path,'rb') as stream: before=stream.read()
            with self.assertRaises(r.ReservationRefused):
                r.ProtectedReservationStore(self.TempProvider(directory),owner=OWNER).reserve('ONE_COMPARISON',NONCE,PAYLOAD)
            with open(path,'rb') as stream: self.assertEqual(stream.read(),before)
    def test_partial_write_remains_consumed_after_new_store_instance(self):
        with tempfile.TemporaryDirectory(prefix='kapit-public-reservation-') as directory:
            with self.assertRaises(r.ReservationRefused):
                r.ProtectedReservationStore(self.TempProvider(directory,True),owner=OWNER).reserve('FRESH_PREFLIGHT',NONCE,PAYLOAD)
            with open(os.path.join(directory,NONCE+'.reservation'),'rb') as stream: self.assertEqual(stream.read(),b'{"a')
            with self.assertRaises(r.ReservationRefused):
                r.ProtectedReservationStore(self.TempProvider(directory),owner=OWNER).reserve('FRESH_PREFLIGHT',NONCE,PAYLOAD)


class CandidateCallbackTests(unittest.TestCase):
    def test_successful_transfer_uses_close_captured_before_acquisition(self):
        provider=SimpleNamespace()
        for name in ('c','w','owner','_basic','_info','_kind','_read','_write','_seek',
                     '_flush','_security','_control','_sidtext','_acl','_ace','_free'):
            setattr(provider,name,lambda *a:1)
        closed=[]
        original_close=lambda handle:closed.append(handle) or 1
        provider._close=lambda *a: (_ for _ in ()).throw(AssertionError('replacement after acquisition'))
        owned=r._transfer_win32(provider,456,original_close)
        owned.close(); owned.close()
        self.assertEqual(closed,[456])
    def test_native_handle_transfer_failure_closes_captured_original_exactly_once(self):
        class BrokenProvider:
            @property
            def c(self): raise OSError('synthetic capture failure')
        closed=[]
        with self.assertRaises(r.ReservationRefused) as caught:
            r._transfer_win32(BrokenProvider(),812,lambda handle:closed.append(handle) or 1)
        self.assertEqual(closed,[812]); self.assertIsNone(caught.exception.__context__)
    def test_ancestor_capture_transfers_failure_cleanup_exactly_once(self):
        for fail_at in (1,2):
            with self.subTest(fail_at=fail_at):
                obj=File(directory=True); identity=obj.identity; calls=[]
                def observed():
                    calls.append(1)
                    if len(calls)==fail_at: raise OSError('synthetic failure')
                    return identity()
                obj.identity=observed
                with self.assertRaises(r.ReservationRefused):
                    r._capture_ancestor(obj,owner=OWNER,repository_root=False)
                self.assertEqual(obj.closes,1)
    def test_ancestor_actual_owner_is_held_but_repository_owner_is_required(self):
        obj=File(directory=True); obj.facts['owner']='S-1-5-18'; obj.facts['private']=False
        held=r._capture_ancestor(obj,owner=OWNER,repository_root=False)
        self.assertEqual(held.original_identity['owner'],'S-1-5-18'); held.close()
        obj=File(directory=True); obj.facts['owner']='S-1-5-18'
        with self.assertRaises(r.ReservationRefused):
            r._capture_ancestor(obj,owner=OWNER,repository_root=True)
        self.assertEqual(obj.closes,1)
    def test_owned_native_read_and_close_capture_original_callbacks_without_windows(self):
        import ctypes as c
        from ctypes import wintypes as w
        events=[]
        def original_read(handle,buffer,maximum,count,overlap):
            events.append(('read',handle)); c.memmove(buffer,b'abc',3)
            c.cast(count,c.POINTER(w.DWORD))[0]=3; return 1
        provider=SimpleNamespace(c=c,w=w,owner=OWNER)
        for name in ('_basic','_info','_kind','_write','_flush','_security','_control',
                     '_sidtext','_acl','_ace','_free'):
            setattr(provider,name,lambda *a:1)
        provider._seek=lambda *a:1
        provider._read=original_read
        provider._close=lambda handle:events.append(('close',handle)) or 1
        original=r._Win32Owned(provider,901)
        provider._read=lambda *a: (_ for _ in ()).throw(AssertionError('substitution'))
        provider._close=lambda *a: (_ for _ in ()).throw(AssertionError('substitution'))
        self.assertEqual(original.read(4),b'abc'); original.close()
        self.assertEqual(events,[('read',901),('close',901)])


if __name__=='__main__': unittest.main()
