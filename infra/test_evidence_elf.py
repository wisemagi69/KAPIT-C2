"""Synthetic ELF byte/parser/closure tests only. Never execute an ELF."""
from dataclasses import FrozenInstanceError
import hashlib
import struct
import unittest

from infra import evidence_elf as elf


def image(*, soname=None, needed=(), rpath=None, runpath=None, extra=()):
    strings=bytearray(b'\x00');entries=[]
    def string(value):
        offset=len(strings);strings.extend(value.encode('ascii')+b'\x00');return offset
    for name in needed:entries.append((1,string(name)))
    if soname is not None:entries.append((14,string(soname)))
    if rpath is not None:entries.append((15,string(rpath)))
    if runpath is not None:entries.append((29,string(runpath)))
    table=((0x200+(len(entries)+len(extra)+3)*16+255)//256)*256
    dynamic=[(5,0x1000+table),(10,len(strings)),*entries,*extra,(0,0)]
    size=table+len(strings)
    raw=bytearray(size)
    ident=b'\x7fELF\x02\x01\x01'+b'\x00'*9
    struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,ident,3,62,1,0,64,0,0,64,56,2,0,0,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,4,0,0x1000,0,size,size,4096)
    struct.pack_into('<IIQQQQQQ',raw,120,2,6,0x200,0x1200,0,len(dynamic)*16,len(dynamic)*16,8)
    for i,row in enumerate(dynamic):struct.pack_into('<qQ',raw,0x200+i*16,*row)
    raw[table:]=strings
    return bytes(raw)


def changed(raw,offset,fmt,value):
    result=bytearray(raw);struct.pack_into(fmt,result,offset,value);return bytes(result)


def artifact(path,**kwargs):return elf.Artifact(path,image(**kwargs))


class ElfParserTests(unittest.TestCase):
    def denied(self,raw):
        with self.assertRaises(elf.ElfUnavailable) as caught:elf.parse_elf(raw)
        self.assertEqual(str(caught.exception),'ELF_CLOSURE_UNAVAILABLE')

    def test_actual_bytes_identity_dependencies_soname_and_paths_are_frozen(self):
        raw=image(soname='libscan.so.1',needed=('libc.so.6','libz.so.1'),runpath=elf.CLAMAV+':'+elf.CLOSURE)
        value=elf.parse_elf(raw)
        self.assertEqual(value.sha256,hashlib.sha256(raw).hexdigest());self.assertEqual(value.size,len(raw))
        self.assertEqual(value.needed,('libc.so.6','libz.so.1'));self.assertEqual(value.soname,'libscan.so.1')
        self.assertEqual(value.runpath,(elf.CLAMAV,elf.CLOSURE));self.assertEqual(value.rpath,())
        with self.assertRaises(FrozenInstanceError):value.soname='other'

    def test_exact_class_byte_order_machine_type_version_header_and_table_bounds(self):
        raw=image()
        for offset,fmt,value in ((4,'B',1),(5,'B',2),(6,'B',0),(7,'B',255),(8,'B',1),
            (16,'<H',2),(18,'<H',183),(20,'<I',2),(32,'<Q',2**64-1),(48,'<I',1),
            (52,'<H',63),(54,'<H',55),(56,'<H',0),(56,'<H',129),(40,'<Q',80),(60,'<H',1),(62,'<H',65535)):
            self.denied(changed(raw,offset,fmt,value))
        for invalid in (raw[:63],raw[:150],bytearray(raw),None):self.denied(invalid)

    def test_file_virtual_arithmetic_alignment_and_dynamic_mapping_bounds(self):
        raw=image()
        for offset,fmt,value in ((72,'<Q',2**64-1),(96,'<Q',len(raw)+1),(104,'<Q',len(raw)-1),
            (80,'<Q',2**64-1),(112,'<Q',3),(112,'<Q',2**33),(68,'<I',7),
            (128,'<Q',len(raw)-1),(136,'<Q',0x9000),(152,'<Q',15),(152,'<Q',65552),(152,'<Q',17)):
            self.denied(changed(raw,offset,fmt,value))
        self.denied(changed(raw,120,'<I',1))  # No dynamic segment.
        self.denied(changed(raw,64,'<I',2))  # No load / duplicate dynamic segment.

    def test_overlapping_virtual_or_file_loads_are_not_guessed(self):
        raw=bytearray(image())
        struct.pack_into('<H',raw,56,3)
        struct.pack_into('<IIQQQQQQ',raw,176,1,4,0,0x1000,0,64,64,1)
        self.denied(bytes(raw))
        struct.pack_into('<Q',raw,192,0x9000)  # Distinct virtual range, overlapping file bytes.
        self.denied(bytes(raw))

    def test_dynamic_terminator_duplicate_tags_hooks_unknown_tags_and_needed_duplicates(self):
        raw=image(soname='libok.so.1')
        dynamic_size=struct.unpack_from('<Q',raw,152)[0]
        self.denied(changed(raw,0x200+dynamic_size-16,'<q',21))
        self.denied(image(extra=((0,0),(21,0))))
        for tag in (5,10,14,15,29):
            kwargs={'soname':'libok.so.1','rpath':elf.CLAMAV,'runpath':elf.CLOSURE}
            self.denied(image(**kwargs,extra=((tag,1),)))
        for tag in (0x7fffffff,0x7ffffffd,0x6ffffefc,0x6ffffefb,31,-1):self.denied(image(extra=((tag,1),)))
        self.denied(image(needed=('liba.so','liba.so')))

    def test_stringtable_pointer_size_termination_empty_and_unsafe_names(self):
        raw=image(needed=('libok.so',))
        for offset,value in ((0x208,0x9000),(0x218,0),(0x218,1048577),(0x228,999999)):
            self.denied(changed(raw,offset,'<Q',value))
        value=bytearray(raw);value[-1]=65;self.denied(bytes(value))
        for name in ('','../libc.so.6','/lib/libc.so.6','lib:bad.so','name\n.so','..'):
            self.denied(image(needed=(name,)));self.denied(image(soname=name))
        for paths in (':'+elf.CLAMAV,elf.CLAMAV+':',elf.CLAMAV+':'+elf.CLAMAV):self.denied(image(rpath=paths))
        self.denied(image(needed=tuple('lib'+str(i)+'.so' for i in range(129))))


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.root=artifact('/opt/clamav/lib/libclamav.so.12.0.3',soname='libclamav.so.12',needed=('libz.so.1','libc.so.6'),
                           runpath=elf.CLAMAV+':'+elf.CLOSURE)
        self.libc=artifact('/usr/lib/x86_64-linux-gnu/libc.so.6',soname='libc.so.6',needed=('ld-linux-x86-64.so.2',))
        self.loader=artifact('/lib64/ld-linux-x86-64.so.2',soname='ld-linux-x86-64.so.2')
        self.libz=artifact('/builder/deps/libz.so.1.2.13',soname='libz.so.1',needed=('libc.so.6',))

    def resolve(self,**kwargs):
        return elf.resolve_closure(**({'roots':(self.root,),'base':(self.libc,self.loader),'candidates':(self.libz,)}|kwargs))

    def denied(self,**kwargs):
        with self.assertRaises(elf.ElfUnavailable) as caught:self.resolve(**kwargs)
        self.assertEqual(str(caught.exception),'ELF_CLOSURE_UNAVAILABLE')

    def test_recursive_actual_byte_resolution_produces_only_regular_copy_plan(self):
        result=self.resolve();paths={item.destination:item for item in result.copies}
        self.assertEqual(set(paths),{elf.CLAMAV+'/libclamav.so.12.0.3',elf.CLAMAV+'/libclamav.so.12',elf.CLOSURE+'/libz.so.1'})
        self.assertEqual(paths[elf.CLOSURE+'/libz.so.1'].data,self.libz.data)
        self.assertEqual(paths[elf.CLOSURE+'/libz.so.1'].sha256,hashlib.sha256(self.libz.data).hexdigest())
        self.assertEqual(len(result.edges),4)
        self.assertFalse(any('/libc.' in name or '/ld-' in name for name in paths))
        self.assertFalse(hasattr(result,'runtime_eligible'))

    def test_missing_ambiguous_and_duplicate_alias_providers_refuse(self):
        self.denied(candidates=())
        other=artifact('/builder/other/libz.so.1',soname='libz.so.1')
        self.denied(candidates=(self.libz,other))
        self.denied(base=(self.libc,self.loader,elf.Artifact('/lib/x86_64-linux-gnu/libc.so.6',self.libc.data)))
        self.denied(candidates=(self.libz,self.libz))

    def test_glibc_loader_families_can_only_be_actual_base_providers(self):
        for name in ('libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libresolv.so.2',
                     'libutil.so.1','libanl.so.1','ld-linux-x86-64.so.2'):
            forbidden=artifact('/builder/deps/'+name,soname=name)
            self.denied(candidates=(self.libz,forbidden))
        self.denied(base=(self.loader,))
        # Renaming the filename does not hide a protected SONAME.
        self.denied(candidates=(self.libz,artifact('/builder/deps/renamed.so',soname='libc.so.6')))

    def test_glibc_companion_shadowing_refuses_but_actual_base_bytes_resolve(self):
        names=('libmvec.so.1','libBrokenLocale.so.1','libthread_db.so.1','libnss_files.so.2',
               'libnss_dns.so.2','libnss_custom_backend.so.2','libmemusage.so','libpcprofile.so',
               'libSegFault.so','libc_malloc_debug.so.0','libnsl.so.1','libm-2.36.so','ld.so')
        for name in names:
            shadow=artifact('/builder/deps/'+name,soname=name,needed=('libc.so.6',))
            self.denied(candidates=(self.libz,shadow))
            self.denied(candidates=(self.libz,artifact('/builder/deps/renamed.so',soname=name)))
            base_artifact=elf.Artifact('/usr/lib/x86_64-linux-gnu/'+name,shadow.data)
            root=artifact(self.root.path,soname='libclamav.so.12',needed=(name,))
            result=self.resolve(roots=(root,),base=(self.libc,self.loader,base_artifact),candidates=())
            self.assertIn((root.path,name,base_artifact.path),result.edges)
            self.assertFalse(any(copy.destination.endswith('/'+name) for copy in result.copies))
            row=next(row for row in result.inventory if row.path==base_artifact.path)
            self.assertEqual(row.origin,'base')
            self.assertEqual(row.sha256,hashlib.sha256(base_artifact.data).hexdigest())

    def test_unreviewed_rpath_runpath_and_simultaneous_paths_refuse(self):
        for paths in ({'rpath':'/tmp'}, {'runpath':'$ORIGIN'}, {'runpath':elf.CLAMAV+':/host'},
                      {'rpath':elf.CLAMAV,'runpath':elf.CLOSURE}):
            root=artifact(self.root.path,soname='libclamav.so.12',needed=('libz.so.1',),**paths)
            self.denied(roots=(root,))

    def test_fixed_wheel_origin_tree_resolves_hashed_soname_and_no_other_tree(self):
        lib=artifact(elf.WHEEL_DIRS[1]+'/libjpeg-ab12.so.62',soname='libjpeg-ab12.so.62',needed=('libc.so.6',),rpath='$ORIGIN')
        extension=artifact(elf.WHEEL_DIRS[0]+'/_imaging.cpython-314-x86_64-linux-gnu.so',needed=('libjpeg-ab12.so.62',),
                           rpath='$ORIGIN/../pillow.libs')
        result=self.resolve(roots=(extension,lib),candidates=())
        self.assertEqual({row.destination for row in result.copies},{extension.path,lib.path})
        no_path=artifact(extension.path,needed=('libjpeg-ab12.so.62',))
        self.denied(roots=(no_path,lib),candidates=())
        for path in ('$ORIGIN/../../private','$LIB','$ORIGIN/../other'):
            self.denied(roots=(artifact(extension.path,needed=('libjpeg-ab12.so.62',),rpath=path),lib),candidates=())

    def test_complete_cycles_and_self_cycle_record_all_edges_without_duplicate_copies(self):
        a=artifact('/builder/a.so',soname='a.so',needed=('b.so',));b=artifact('/builder/b.so',soname='b.so',needed=('a.so',))
        root=artifact(self.root.path,soname='libclamav.so.12',needed=('a.so',))
        result=self.resolve(roots=(root,),candidates=(a,b))
        self.assertEqual(result.edges,tuple(sorted(((root.path,'a.so',a.path),(a.path,'b.so',b.path),(b.path,'a.so',a.path)))))
        self.assertEqual(result.cycles,((a.path,b.path,a.path),))
        self.assertEqual(len(result.copies),len({copy.destination for copy in result.copies}))
        own=artifact('/builder/a.so',soname='a.so',needed=('a.so',))
        result=self.resolve(roots=(root,),candidates=(own,))
        self.assertEqual(result.cycles,((own.path,own.path),))
        self.assertEqual(len(result.edges),2)

    def test_cycle_cannot_skip_missing_ambiguous_bad_search_or_mismatched_soname_tail(self):
        root=artifact(self.root.path,needed=('a.so',))
        a=artifact('/builder/a.so',soname='a.so',needed=('b.so',))
        b=artifact('/builder/b.so',soname='b.so',needed=('a.so','tail.so'))
        tail=artifact('/builder/tail.so',soname='tail.so')
        self.denied(roots=(root,),candidates=(a,b))
        self.denied(roots=(root,),candidates=(a,b,tail,artifact('/builder/duplicate.so',soname='tail.so')))
        self.denied(roots=(root,),candidates=(a,b,artifact('/builder/tail.so',soname='wrong.so')))
        self.denied(roots=(root,),candidates=(a,b,artifact('/builder/tail.so',soname='tail.so',runpath='/tmp')))
        self.denied(roots=(root,),candidates=(a,b,tail,artifact('/builder/libmvec.so.1',soname='libmvec.so.1')))
        self.denied(roots=(root,),candidates=(a,b,elf.Artifact(tail.path,b'malformed ELF')))

    def test_actual_freetype_harfbuzz_metadata_shape_is_finite_with_external_base_edges(self):
        prefix=elf.WHEEL_DIRS[1]+'/'
        ft='libfreetype-57f805ba.so.6.20.6';hb='libharfbuzz-fb49c9fc.so.0.61450.0'
        freetype=artifact(prefix+ft,soname=ft,needed=(hb,'libc.so.6'),rpath='$ORIGIN')
        harfbuzz=artifact(prefix+hb,soname=hb,needed=(ft,'libc.so.6'),rpath='$ORIGIN')
        result=self.resolve(roots=(freetype,harfbuzz),candidates=())
        self.assertEqual(result.cycles,((freetype.path,harfbuzz.path,freetype.path),))
        self.assertEqual(len(result.edges),5)
        self.assertEqual({row.destination for row in result.copies},{freetype.path,harfbuzz.path})
        self.assertEqual(result,self.resolve(roots=(harfbuzz,freetype),candidates=()))

    def test_depth_and_input_inventory_bounds_still_refuse(self):
        chain=tuple(artifact('/builder/lib'+str(i)+'.so',soname='lib'+str(i)+'.so',
            needed=('lib'+str(i+1)+'.so',) if i<33 else ()) for i in range(34))
        self.denied(roots=(artifact(self.root.path,needed=('lib0.so',)),),candidates=chain)
        self.denied(roots=[]);self.denied(roots=())
        self.denied(candidates=tuple(self.libz for _ in range(256)))

    def test_reached_node_and_edge_caps_remain_enforced_with_cycle_support(self):
        leaves=tuple(artifact('/builder/leaf'+str(i)+'.so',soname='leaf'+str(i)+'.so') for i in range(128))
        root=artifact(self.root.path,needed=tuple('leaf'+str(i)+'.so' for i in range(127)))
        accepted=self.resolve(roots=(root,),candidates=leaves[:127])
        self.assertEqual(len(accepted.edges),127)
        self.denied(roots=(artifact(root.path,needed=tuple('leaf'+str(i)+'.so' for i in range(128))),),candidates=leaves)
        common=tuple(artifact('/usr/lib/x86_64-linux-gnu/common'+str(i)+'.so',soname='common'+str(i)+'.so') for i in range(9))
        dependencies=tuple('common'+str(i)+'.so' for i in range(9))
        dense=tuple(artifact('/builder/dense'+str(i)+'.so',soname='dense'+str(i)+'.so',needed=dependencies) for i in range(112))
        self.denied(roots=(artifact(root.path,needed=tuple('dense'+str(i)+'.so' for i in range(112))),),base=common,candidates=dense)

    def test_absolute_inventory_paths_only_and_no_declared_pass_or_hash_authority(self):
        for path in ('../lib.so','/builder/../lib.so','/builder//lib.so','/builder/lib.so/','C:/lib.so'):
            self.denied(candidates=(elf.Artifact(path,self.libz.data),))
        self.denied(candidates=({'path':self.libz.path,'data':self.libz.data,'PASS':True},))
        self.denied(roots=(elf.Artifact('/tmp/clamav.so',self.root.data),))
        self.denied(candidates=(elf.Artifact(self.libz.path,b'not an ELF'),))


if __name__=='__main__':unittest.main()
