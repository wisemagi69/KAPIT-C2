"""Pure fake IO/FFI tests. No native scanner, containers or scratch mutation."""
from contextlib import contextmanager
import ctypes
from copy import deepcopy
import errno
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from infra.native import scratch_probe as probe


def encoded(value): return json.dumps(value, separators=(',', ':')).encode('ascii')


class Entry:
    def __init__(self, mode): self.mode = mode; self.calls = []
    @property
    def name(self): raise AssertionError('Names must not be read')
    @property
    def path(self): raise AssertionError('Paths must not be read')
    def stat(self, *, follow_symlinks):
        self.calls.append(follow_symlinks)
        if isinstance(self.mode, BaseException): raise self.mode
        return SimpleNamespace(st_mode=self.mode)


@contextmanager
def directory(entries): yield iter(entries)


class Native:
    def __init__(self, value=0, error=0, raises=None):
        self.value = value; self.error = error; self.raises = raises; self.calls = []
    def __call__(self, *args):
        self.calls.append(args)
        if self.raises: raise self.raises
        ctypes.set_errno(self.error)
        return self.value


def worker_fixture(*, strict='SCAN_CLEAN', upstream=0, close_error=None, fmap=7, unmap_error=None):
    class ScanOptions(ctypes.Structure):
        _fields_ = [(name,ctypes.c_uint32) for name in ('general','parse','heuristic','mail','dev')]
    strict_fn = Native()
    strict_fn.argtypes = (ctypes.c_void_p,ctypes.c_char_p,ctypes.POINTER(ctypes.c_char_p),
                          ctypes.POINTER(ctypes.c_ulong),ctypes.c_void_p,
                          ctypes.POINTER(ScanOptions),ctypes.c_void_p)
    strict_fn.restype = ctypes.c_int
    library = SimpleNamespace(cl_kapit_scanmap_strict_v1=strict_fn,
                              cl_scanmap_callback=Native(upstream), cl_fmap_open_memory=Native(fmap),
                              cl_fmap_close=Native(raises=unmap_error))
    scanner = SimpleNamespace(library=library, engine=23, scan=Mock(return_value=strict),
                              close=Mock(side_effect=close_error),_check_limits=Mock())
    worker = SimpleNamespace(c=ctypes, ScanOptions=ScanOptions, load_configuration=Mock(),
                             _public_images=Mock(return_value=(('image/png',b'P'*45),('image/jpeg',b'J'*40))),
                             NativeScanner=Mock(return_value=scanner))
    return worker, scanner


def complete_lifecycle():
    return {**probe._base('lifecycle'), 'completed':True, 'failed_stage':'NONE',
            'snapshots':[{'stage':stage,'counts':dict.fromkeys(probe.TYPES,0),
                          'scan':'CLEAN' if stage in ('strict_png','upstream_png') else 'NONE'} for stage in probe.STAGES]}


class ScratchProbeTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(probe.sys,'platform','linux'))

    def test_nonlinux_runtime_refuses_before_scratch_or_native_io(self):
        with patch.object(probe.sys,'platform','win32'),patch.object(probe.os,'scandir') as query, \
             patch.object(probe.os,'mkdir') as mkdir,patch.object(ctypes,'CDLL') as native,patch.object(probe,'_worker') as worker:
            for operation in ('rmdir','lifecycle'):
                result=probe.run(operation)
                self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],'fresh_start')
                self.assertEqual(probe.parse_result(encoded(result),operation),result)
            with self.assertRaises(probe.ProbeUnavailable):probe._snapshot()
            query.assert_not_called();mkdir.assert_not_called();native.assert_not_called();worker.assert_not_called()
    def test_import_is_inert_and_source_bounded(self):
        source=Path(probe.__file__).read_bytes()
        self.assertLessEqual(len(source),16384)
        spec=importlib.util.spec_from_file_location('scratch_inert',probe.__file__)
        module=importlib.util.module_from_spec(spec)
        with patch.object(ctypes,'CDLL') as native, patch.object(probe.os,'scandir') as query, patch.object(probe.os,'mkdir') as mkdir:
            spec.loader.exec_module(module)
        native.assert_not_called();query.assert_not_called();mkdir.assert_not_called()

    def test_metadata_snapshot_uses_only_lstat_type_no_names(self):
        entries=[Entry(stat.S_IFREG),Entry(stat.S_IFDIR),Entry(stat.S_IFLNK),Entry(stat.S_IFIFO)]
        with patch.object(probe.os,'scandir',return_value=directory(entries)) as query:
            self.assertEqual(probe._snapshot(),dict.fromkeys(probe.TYPES,1))
        query.assert_called_once_with('/scratch')
        self.assertTrue(all(entry.calls==[False] for entry in entries))

    def test_snapshot_64_allowed_65th_read_refuses_before_stat(self):
        for count in (64,65):
            entries=[Entry(stat.S_IFDIR) for _ in range(count)]
            with patch.object(probe.os,'scandir',return_value=directory(entries)):
                if count==64:self.assertEqual(probe._snapshot()['directory'],64)
                else:
                    with self.assertRaises(probe.ProbeUnavailable):probe._snapshot()
                    self.assertEqual(entries[-1].calls,[])

    def test_query_or_iterator_close_failure_refuses(self):
        @contextmanager
        def close_failure():
            yield iter(())
            raise OSError('secret path')
        for item in (directory([Entry(OSError('secret'))]),close_failure()):
            with patch.object(probe.os,'scandir',return_value=item), self.assertRaises(OSError):probe._snapshot()

    def run_rmdir(self, fn, *, snapshot=None, create_error=None, mode=stat.S_IFDIR, contents=()):
        snapshot=dict.fromkeys(probe.TYPES,0) if snapshot is None else snapshot
        with patch.object(probe,'_snapshot',return_value=snapshot), \
             patch.object(probe.os,'mkdir',side_effect=create_error) as mkdir, \
             patch.object(probe.os,'lstat',return_value=SimpleNamespace(st_mode=mode)), \
             patch.object(probe.os,'scandir',return_value=directory(contents)), \
             patch.object(ctypes,'CDLL',return_value=SimpleNamespace(rmdir=fn)) as loader:
            result=probe.run('rmdir')
        return result,mkdir,loader

    def test_rmdir_three_closed_observations_exact_native_abi_and_single_attempt(self):
        for code,error,expected in ((0,0,'REMOVED'),(0,errno.EPERM,'REMOVED'),(-1,errno.EPERM,'EPERM'),(-1,errno.EACCES,'OTHER_ERRNO')):
            fn=Native(code,error)
            result,mkdir,loader=self.run_rmdir(fn)
            self.assertTrue(result['completed']);self.assertEqual(result['observation'],expected)
            self.assertEqual(result['snapshots'],[])
            mkdir.assert_called_once_with('/scratch/kapit-public-rmdir-probe',0o700)
            loader.assert_called_once_with(None,use_errno=True)
            self.assertEqual(fn.argtypes,[ctypes.c_char_p]);self.assertIs(fn.restype,ctypes.c_int)
            self.assertEqual(fn.calls,[(b'/scratch/kapit-public-rmdir-probe',)])

    def test_rmdir_invalid_native_return_or_errno_is_failure_without_retry(self):
        for code,error in ((True,0),(1,0),(-2,errno.EPERM),(-1,0),(-1,4096)):
            fn=Native(code,error);result,_,_=self.run_rmdir(fn)
            self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],'remove_directory')
            self.assertEqual(result['observation'],'NONE');self.assertEqual(len(fn.calls),1)

    def test_rmdir_post_success_update_interrupt_cannot_preserve_success(self):
        class InterruptedResult(dict):
            def update(self, *args, **kwargs):
                super().update(*args,**kwargs)
                if kwargs.get('completed') is True:raise KeyboardInterrupt('private')
        initial=InterruptedResult(probe._base('rmdir'))
        with patch.object(probe,'_base',return_value=initial):
            result,_,_=self.run_rmdir(Native())
        self.assertFalse(result['completed']);self.assertEqual(result['observation'],'NONE')
        self.assertEqual(result['failed_stage'],'remove_directory')

    def test_rmdir_fresh_nonempty_or_wrong_created_type_refuses(self):
        fn=Native()
        result,mkdir,loader=self.run_rmdir(fn,snapshot={'regular':0,'directory':1,'symlink':0,'other':0})
        self.assertEqual(result['failed_stage'],'fresh_start');mkdir.assert_not_called();loader.assert_not_called()
        for mode,contents in ((stat.S_IFLNK,()),(stat.S_IFDIR,(object(),))):
            result,_,loader=self.run_rmdir(fn,mode=mode,contents=contents)
            self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],'create_directory')
            loader.assert_not_called()
        self.assertEqual(fn.calls,[])

    def test_rmdir_create_native_exception_and_abi_error_no_raw_data(self):
        for fn,create_error,stage in ((Native(),OSError('secret'),'create_directory'),
                                      (Native(raises=OSError('secret')),None,'remove_directory')):
            result,_,_=self.run_rmdir(fn,create_error=create_error)
            self.assertEqual(result['failed_stage'],stage);self.assertNotIn('secret',encoded(result).decode())
        with patch.object(probe,'_snapshot',return_value=dict.fromkeys(probe.TYPES,0)), \
             patch.object(probe.os,'mkdir'),patch.object(probe.os,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR)), \
             patch.object(probe.os,'scandir',return_value=directory(())),patch.object(ctypes,'CDLL',side_effect=AttributeError('secret')):
            self.assertEqual(probe.run('rmdir')['failed_stage'],'native_abi')

    def lifecycle(self, worker, *, snapshot_error=None, counts=None):
        calls=[]
        def snapshot():
            calls.append('snapshot')
            if snapshot_error == len(calls):raise OSError('private-name')
            return dict.fromkeys(probe.TYPES,0) if counts is None else counts
        with patch.object(probe,'_snapshot',side_effect=snapshot),patch.object(probe,'_worker',return_value=worker):
            return probe.run('lifecycle'),calls

    def test_lifecycle_exact_five_snapshots_strict_unchanged_and_upstream_abi(self):
        worker,scanner=worker_fixture();result,calls=self.lifecycle(worker)
        self.assertTrue(result['completed']);self.assertEqual(len(calls),5)
        self.assertEqual(tuple(row['stage'] for row in result['snapshots']),probe.STAGES)
        scanner.scan.assert_called_once_with(b'P'*45,'image/png');scanner.close.assert_called_once_with()
        worker.load_configuration.assert_called_once_with();worker.NativeScanner.assert_called_once_with()
        lib=scanner.library
        expected=(ctypes.c_void_p,ctypes.c_char_p,ctypes.POINTER(ctypes.c_char_p),
                  ctypes.POINTER(ctypes.c_ulong),ctypes.c_void_p,
                  ctypes.POINTER(worker.ScanOptions),ctypes.c_void_p)
        self.assertEqual(lib.cl_kapit_scanmap_strict_v1.argtypes,expected)
        self.assertIs(lib.cl_scanmap_callback.argtypes,lib.cl_kapit_scanmap_strict_v1.argtypes)
        self.assertIs(lib.cl_scanmap_callback.restype,lib.cl_kapit_scanmap_strict_v1.restype)
        args=lib.cl_scanmap_callback.calls[0]
        self.assertEqual(len(args),7)
        for declared,actual in zip(expected,args):declared.from_param(actual)
        self.assertEqual((args[0],args[1],args[4],args[6]),(7,None,23,None))
        self.assertIs(type(args[2]._obj),ctypes.c_char_p)
        self.assertIs(type(args[3]._obj),ctypes.c_ulong)
        self.assertIs(type(args[5]._obj),worker.ScanOptions)
        self.assertEqual([getattr(args[5]._obj,name) for name in ('general','parse','heuristic','mail','dev')],[4,2048,8196,0,0])
        map_args=lib.cl_fmap_open_memory.calls[0]
        self.assertIs(type(map_args[0]),ctypes.c_void_p)
        self.assertEqual(map_args[1],45)
        buffers=[value for value in map_args[0]._objects.values() if isinstance(value,ctypes.Array)]
        self.assertEqual(len(buffers),1);self.assertEqual(buffers[0].raw,b'P'*45+b'\0')
        self.assertEqual(lib.cl_fmap_close.calls,[(7,)])
        self.assertEqual(scanner._check_limits.call_count,2)

    def test_upstream_limit_check_failure_refuses_and_preserves_map_cleanup(self):
        for failure_at in (1,2):
            worker,scanner=worker_fixture()
            scanner._check_limits.side_effect=[ValueError('secret')] if failure_at==1 else [None,ValueError('secret')]
            result,_=self.lifecycle(worker)
            self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],'upstream_png')
            scanner.close.assert_called_once_with()
            self.assertEqual(scanner.library.cl_fmap_close.calls,[] if failure_at==1 else [(7,)])

    def test_fresh_snapshot_precedes_worker_import_and_all_native_work(self):
        with patch.object(probe,'_snapshot',side_effect=OSError('private')),patch.object(probe,'_worker') as worker:
            result=probe.run('lifecycle')
        self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],'fresh_start');worker.assert_not_called()

    def test_worker_import_configuration_images_constructor_and_scan_failures_are_finite(self):
        with patch.object(probe,'_snapshot',return_value=dict.fromkeys(probe.TYPES,0)), \
             patch.object(probe,'_worker',side_effect=ImportError('secret')):
            self.assertEqual(probe.run('lifecycle')['failed_stage'],'worker_import')
        for method,stage in (('load_configuration','configuration'),('_public_images','public_images'),
                             ('NativeScanner','scanner_initialization')):
            worker,scanner=worker_fixture();getattr(worker,method).side_effect=ValueError('secret')
            result,_=self.lifecycle(worker)
            self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],stage)
            scanner.close.assert_not_called()
        worker,scanner=worker_fixture();scanner.scan.side_effect=ValueError('secret')
        result,_=self.lifecycle(worker)
        self.assertEqual(result['failed_stage'],'strict_png');scanner.close.assert_called_once_with()

    def test_cli_refuses_missing_extra_or_unknown_operation_before_io(self):
        for argv in (['scratch_probe'],['scratch_probe','other'],['scratch_probe','rmdir','/arbitrary']):
            with patch.object(probe.sys,'argv',argv),patch.object(probe,'run') as run:
                self.assertEqual(probe.main(),2);run.assert_not_called()

    def test_cli_unexpected_parser_or_transport_error_emits_no_raw_traceback(self):
        for error in (ValueError('secret native path'),KeyboardInterrupt('secret')):
            with patch.object(probe.sys,'argv',['scratch_probe','lifecycle']), \
                 patch.object(probe,'run',side_effect=error),patch('builtins.print') as output:
                self.assertEqual(probe.main(),2);output.assert_not_called()

    def test_scanner_always_closes_on_each_late_snapshot_failure(self):
        for index,stage,prefix in ((2,'scanner_initialization',1),(3,'strict_png',2),(4,'upstream_png',3),(5,'engine_close',4)):
            worker,scanner=worker_fixture();result,_=self.lifecycle(worker,snapshot_error=index)
            self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],stage)
            self.assertEqual(len(result['snapshots']),prefix);scanner.close.assert_called_once_with()

    def test_engine_close_failure_dominates_prior_scan_or_snapshot_failure(self):
        for snapshot_error in (None,2,3,4):
            worker,scanner=worker_fixture(close_error=OSError('secret'))
            result,_=self.lifecycle(worker,snapshot_error=snapshot_error)
            self.assertFalse(result['completed']);self.assertEqual(result['failed_stage'],'engine_close')
            scanner.close.assert_called_once_with();self.assertLess(len(result['snapshots']),5)
            self.assertNotIn('secret',encoded(result).decode())

    def test_exception_after_fourth_append_cannot_become_success(self):
        class InterruptedRows(list):
            def append(self, value):
                super().append(value)
                if len(self)==4:raise KeyboardInterrupt('private')
        result=probe._base('lifecycle');result['snapshots']=InterruptedRows()
        worker,scanner=worker_fixture()
        with patch.object(probe,'_base',return_value=result):
            measured,_=self.lifecycle_raw(worker)
        self.assertFalse(measured['completed']);self.assertEqual(measured['failed_stage'],'lifecycle_finalization')
        scanner.close.assert_called_once_with();self.assertEqual(len(measured['snapshots']),4)
        measured['snapshots']=list(measured['snapshots'])
        self.assertFalse(probe.parse_result(encoded(measured),'lifecycle')['completed'])

    def lifecycle_raw(self, worker):
        with patch.object(probe,'_snapshot',return_value=dict.fromkeys(probe.TYPES,0)),patch.object(probe,'_worker',return_value=worker):
            return probe._lifecycle(),None

    def test_upstream_fmap_close_always_and_failure_refuses(self):
        for code in (0,1,2,True):
            worker,scanner=worker_fixture(upstream=code)
            if type(code) is int:
                self.assertEqual(probe._upstream(worker,scanner,b'P'*45),{0:'CLEAN',1:'NOT_CLEAN',2:'ERROR'}[code])
            else:
                with self.assertRaises(probe.ProbeUnavailable):probe._upstream(worker,scanner,b'P'*45)
            self.assertEqual(scanner.library.cl_fmap_close.calls,[(7,)])
        worker,scanner=worker_fixture(unmap_error=OSError('secret'));result,_=self.lifecycle(worker)
        self.assertEqual(result['failed_stage'],'upstream_png');scanner.close.assert_called_once_with()
        worker,scanner=worker_fixture(fmap=0);result,_=self.lifecycle(worker)
        self.assertEqual(result['failed_stage'],'upstream_png');self.assertEqual(scanner.library.cl_fmap_close.calls,[])

    def test_upstream_preserves_full_width_fmap_identity(self):
        address=(1<<48)+0x1234
        worker,scanner=worker_fixture(fmap=address)
        result,_=self.lifecycle(worker)
        self.assertTrue(result['completed'])
        self.assertEqual(scanner.library.cl_scanmap_callback.calls[0][0],address)
        self.assertEqual(scanner.library.cl_fmap_close.calls,[(address,)])

    def test_nonclean_scan_categories_are_measurements_without_native_eligibility(self):
        worker,_=worker_fixture(strict='SCAN_NOT_CLEAN',upstream=2);result,_=self.lifecycle(worker)
        self.assertTrue(result['completed']);self.assertEqual(result['snapshots'][2]['scan'],'NOT_CLEAN')
        self.assertEqual(result['snapshots'][3]['scan'],'ERROR');self.assertFalse(result['native_eligible'])

    def test_parser_duplicate_unknown_bool_depth_oversize_and_nonbytes_refuse(self):
        for raw in (b'{}',b'{"schema":1,"schema":1}',b'{"schema":NaN}',b'['*100+b']'*100,
                    b'x'*4097,bytearray(b'{}'),b'\xff'):
            with self.subTest(raw_type=type(raw).__name__),self.assertRaises(probe.ProbeUnavailable):probe.parse_result(raw,'lifecycle')
        for key,value in (('schema',True),('scope','UNKNOWN'),('completed',1),('native_eligible',True),('private_input_allowed',0),('unexpected',False)):
            doc=complete_lifecycle();doc[key]=value
            with self.assertRaises(probe.ProbeUnavailable):probe.parse_result(encoded(doc),'lifecycle')

    def test_parser_wrong_stage_order_unknown_scan_counts_bool_overflow_refuse(self):
        mutations=[lambda d:d['snapshots'].reverse(),lambda d:d['snapshots'][1].update(stage='fresh_start'),
                   lambda d:d['snapshots'][0].update(scan='CLEAN'),lambda d:d['snapshots'][2].update(scan='NONE'),
                   lambda d:d['snapshots'][0]['counts'].update(regular=True),
                   lambda d:d['snapshots'][0]['counts'].update(regular=64,directory=1),
                   lambda d:d['snapshots'][0]['counts'].update(regular=-1),
                   lambda d:d['snapshots'][0].update(name='secret'),lambda d:d['snapshots'].pop()]
        for change in mutations:
            doc=complete_lifecycle();change(doc)
            with self.assertRaises(probe.ProbeUnavailable):probe.parse_result(encoded(doc),'lifecycle')

    def test_parser_partial_contradictions_and_operation_substitution_refuse(self):
        doc=complete_lifecycle()
        for updates in ({'completed':False,'failed_stage':'strict_png'},{'completed':False,'failed_stage':'NONE'},
                        {'completed':True,'failed_stage':'engine_close'},{'observation':'REMOVED'},{'operation':'rmdir'}):
            with self.assertRaises(probe.ProbeUnavailable):probe.parse_result(encoded({**doc,**updates}),'lifecycle')
        for operation in (None,True,'other'):
            with self.assertRaises(probe.ProbeUnavailable):probe.run(operation)
        with self.assertRaises(probe.ProbeUnavailable):
            probe.parse_result(encoded({**probe._base('lifecycle'),'failed_stage':'engine_close'}),'lifecycle')

    def test_rmdir_parser_requires_complete_classification_and_no_snapshots(self):
        good={**probe._base('rmdir'),'completed':True,'failed_stage':'NONE','observation':'EPERM'}
        self.assertEqual(probe.parse_result(encoded(good),'rmdir'),good)
        for updates in ({'observation':'UNKNOWN'},{'failed_stage':'native_abi'},{'completed':False},
                        {'snapshots':[complete_lifecycle()['snapshots'][0]]}):
            with self.assertRaises(probe.ProbeUnavailable):probe.parse_result(encoded({**good,**updates}),'rmdir')


if __name__ == '__main__':unittest.main()
