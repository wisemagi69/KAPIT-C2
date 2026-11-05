"""Fixed existing-build readback only. No build command or retry exists."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import stat
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = '.cache/m1-runtime/private-scanner-build'
CTX = STAGE+'/ctx-interpreter-50db1d9b5ae84facbf2f9dc9b69c968e'
DESCENDANTS = ('builder-debs','patched','patched/libclamav')
FAILED_PARENT = 'ai/state/private-scanner-interpreter-build.json'
FAILED_SHA = 'd1b722e60bc5eecda447422c4b505e1f57f5c0f964b67a290db0330a177e5b54'
DRIVER_RECEIPT = 'ai/state/private-scanner-interpreter-compile-b8925b35c106462cb7fd4edb34afadd8.json'
DRIVER_SHA = 'bc89160017fafa1142665d762e8a5f58d1fd9e6ae80e212ddb4d6a30956a5024'
COMPILER_SOURCE_SHA = '4822490b0d38f487ddd06c1a9760e8c3783dec627634a7bc630179a84e683085'
CONFIG = 'sha256:ce8fbec90eeb1d84bc2e66e86d0399372ed6904ace979fd55c61e31209fe2fbb'
RESERVATION = '35981f09638d40c88f2a09cf7342dc9c'
READBACK = 'ai/state/private-scanner-interpreter-readback.json'
IDENTITY = 'ai/state/private-scanner-interpreter-readback-identity.json'
EXPORT = 'ai/state/private-scanner-interpreter-readback-export.json'
SCOPE = 'PUBLIC_EXISTING_INTERPRETER_BUILD_READBACK_NOT_NATIVE_PROOF'


def modules():
    from infra import evidence_interpreter_compile as compiler
    from infra import evidence_native_refresh_runtime as refresh
    return compiler, refresh


def require(value, code='INTERPRETER_READBACK_REFUSED'):
    if value is not True:
        raise RuntimeError(code)


def validate_acl_shape(owner, user, control, revision, acl_revision, rows, *, protected):
    """Exact specific directory shape; no caller-selected identities or grants."""
    require(type(protected) is bool and type(user) is str and owner == user)
    require(type(control) is int and type(revision) is int and revision == 1
        and type(acl_revision) is int and acl_revision == 2)
    require(control == (0x9004 if protected else 0x8004), 'DIRECTORY_CONTROL_CHANGED')
    expected = [(0,3 if protected else 19,0x1f01ff,sid)
                for sid in (user,'S-1-5-18','S-1-5-32-544')]
    require(type(rows) is list and len(rows) == 3
        and all(type(row) is tuple and len(row) == 4
            and all(type(x) is int for x in row[:3]) and type(row[3]) is str for row in rows)
        and rows == expected, 'DIRECTORY_ACE_CHANGED')


def verify_acl(api, handle, *, protected):
    owner,dacl,descriptor = c.c_void_p(),c.c_void_p(),c.c_void_p()
    try:
        require(api.a.GetSecurityInfo(handle,1,5,c.byref(owner),None,c.byref(dacl),None,c.byref(descriptor)) == 0)
        control,revision = w.WORD(),w.DWORD()
        require(bool(api.a.GetSecurityDescriptorControl(descriptor,c.byref(control),c.byref(revision)))
            and bool(dacl.value), 'DIRECTORY_SECURITY_UNAVAILABLE')
        count = c.c_ushort.from_address(dacl.value+4).value
        require(count == 3, 'DIRECTORY_ACE_CHANGED')
        rows=[]
        for index in range(count):
            ace=c.c_void_p()
            require(bool(api.a.GetAce(dacl,index,c.byref(ace))) and bool(ace.value))
            rows.append((c.c_ubyte.from_address(ace.value).value,
                c.c_ubyte.from_address(ace.value+1).value,
                w.DWORD.from_address(ace.value+4).value,api.sid(ace.value+8)))
        validate_acl_shape(api.sid(owner),api.user,control.value,revision.value,
            c.c_ubyte.from_address(dacl.value).value,rows,protected=protected)
    finally:
        require(not api.k.LocalFree(descriptor),'DIRECTORY_DESCRIPTOR_CLOSE_UNCONFIRMED')


class FileInformation(c.Structure):
    _fields_ = [('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),
        ('write',w.FILETIME),('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),
        ('links',w.DWORD),('index_high',w.DWORD),('index_low',w.DWORD)]


class FileIdentity(c.Structure):
    _fields_ = [('volume',c.c_ulonglong),('identifier',c.c_ubyte*16)]


def directory_identity(api,handle,path):
    """Same retained handle matches the anchored current regular directory."""
    from infra.evidence_tools import checked
    checked(path)
    value=FileInformation()
    query=api.k.GetFileInformationByHandle
    query.argtypes,query.restype=[w.HANDLE,c.POINTER(FileInformation)],w.BOOL
    require(bool(query(handle,c.byref(value))),'DIRECTORY_IDENTITY_UNAVAILABLE')
    # FILE_INFO_BY_HANDLE_CLASS.FileIdInfo is 18. The legacy DWORD serial
    # cannot represent modern stat's full volume identity; never truncate it.
    identity=FileIdentity()
    full_query=api.k.GetFileInformationByHandleEx
    full_query.argtypes,full_query.restype=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL
    require(c.sizeof(FileIdentity) == 24 and FileIdentity.identifier.offset == 8
        and bool(full_query(handle,18,c.byref(identity),c.sizeof(identity))),
        'DIRECTORY_FULL_IDENTITY_UNAVAILABLE')
    identifier=int.from_bytes(bytes(identity.identifier),'little')
    observed=path.stat()
    require(stat.S_ISDIR(observed.st_mode) and not getattr(observed,'st_file_attributes',0)&0x400
        and value.attributes & 0x10 != 0 and not value.attributes & 0x400
        and value.links == observed.st_nlink == 1
        and identity.volume == observed.st_dev and identifier == observed.st_ino,
        'DIRECTORY_IDENTITY_CHANGED')
    return (identity.volume,identifier,value.attributes,value.links)


def directory_role(path):
    require(type(path) is type(ROOT))
    allowed = {ROOT/CTX:True, **{ROOT/CTX/name:False for name in DESCENDANTS}}
    require(path in allowed, 'DIRECTORY_PATH_REFUSED')
    return allowed[path]


@contextmanager
def pin_directory(api,path):
    """Open only four fixed existing paths; never creates or changes security."""
    from infra.evidence_tools import checked
    protected=directory_role(path)
    checked(path)
    handle=api.k.CreateFileW(str(path),0x20000|0x80,3,None,3,0x00200000|0x02000000,None)
    require(handle not in (None,c.c_void_p(-1).value),'DIRECTORY_OPEN_REFUSED')
    before=None
    try:
        before=directory_identity(api,handle,path)
        verify_acl(api,handle,protected=protected)
        yield
    finally:
        try:
            if before is not None:
                require(directory_identity(api,handle,path) == before,'DIRECTORY_IDENTITY_CHANGED')
                verify_acl(api,handle,protected=protected)
        finally:
            require(bool(api.k.CloseHandle(handle)),'DIRECTORY_HANDLE_CLOSE_UNCONFIRMED')


def fixed_build(api,pins):
    compiler,refresh=modules()
    raw=refresh.pin_bytes(ROOT,pins,api,FAILED_PARENT,expected=FAILED_SHA)
    require(len(raw) == 434)
    parent=refresh.document(raw)
    require(parent.get('status') == 'REFUSED' and parent.get('completed') is False
        and parent.get('pins_closed') is False and parent.get('stage') == 'build'
        and parent.get('native_eligible') is False,'FAILED_PARENT_CHANGED')
    raw=refresh.pin_bytes(ROOT,pins,api,DRIVER_RECEIPT,expected=DRIVER_SHA)
    require(len(raw) == 17852)
    value=compiler.validate_build(refresh.document(raw))
    require(value.get('context','').replace('\\','/') == CTX and value.get('iidfile') == CONFIG
        and value.get('reservation') == RESERVATION,'FIXED_BUILD_CHANGED')
    return value


def reconstructed_context(api,pins,value):
    compiler,refresh=modules()
    from infra.evidence_interpreter_build import source_build_inputs, MIN_BUILD_FREE_BYTES
    raws=[refresh.pin_bytes(ROOT,pins,api,STAGE+'/'+name,maximum=256*1024*1024)
        for name in ('clamav-1.4.6.tar.gz','clamav-1.4.6.tar.gz.sig','builder-packages.json','builder-debs.tar')]
    patch=refresh.pin_bytes(ROOT,pins,api,compiler.PIN_NAMES[2],expected=compiler.NEW_PINS[compiler.PIN_NAMES[2]])
    recipe=refresh.pin_bytes(ROOT,pins,api,compiler.PIN_NAMES[1],expected=compiler.NEW_PINS[compiler.PIN_NAMES[1]])
    prepared=source_build_inputs(raws[0],raws[1],patch,raws[2],raws[3],recipe,free_bytes=MIN_BUILD_FREE_BYTES)
    rows={name:{'bytes':len(raw),'sha256':compiler.digest(raw)} for name,raw in prepared.files.items()}
    require(len(rows) == 29 and value['context_files'] == rows,'CONTEXT_ROWS_CHANGED')
    # Parents are opened in ancestry order and remain held through every byte
    # read, action and reverse-order exit ACL/identity/handle-close check.
    for relative in ('',*DESCENDANTS):
        pins.enter_context(pin_directory(api,ROOT/CTX/relative))
    for name,row in rows.items():
        parent=Path(name).parent.as_posix()
        require(parent in ('.',*DESCENDANTS),'CONTEXT_PARENT_REFUSED')
        raw=refresh.pin_bytes(ROOT,pins,api,CTX+'/'+name,private=True,
                              expected=row['sha256'],maximum=256*1024*1024)
        require(len(raw) == row['bytes'],'CONTEXT_BYTES_CHANGED')


def validate_readback(value):
    compiler,_=modules()
    require(type(value) is dict and value.get('schema') == 1 and type(value.get('schema')) is int
        and value.get('scope') == SCOPE and value.get('stage') == 'readback'
        and value.get('status') == 'VERIFIED' and value.get('completed') is True
        and value.get('pins_closed') is True and value.get('failed_parent_retained_refused') is True
        and value.get('failed_parent_sha256') == FAILED_SHA and value.get('driver_receipt') == DRIVER_RECEIPT
        and value.get('driver_receipt_sha256') == DRIVER_SHA and value.get('config_digest') == CONFIG
        and value.get('source_pins') == compiler.NEW_PINS
        and value.get('native_eligible') is False and value.get('private_input_allowed') is False
        and value.get('control_state_modified') is False
        and 'failure_code' not in value and 'exception_class' not in value,
        'READBACK_PROVENANCE_REFUSED')


def identity(api,pins,call,build,result):
    compiler,refresh=modules()
    saved=refresh.document(refresh.pin_bytes(ROOT,pins,api,READBACK))
    validate_readback(saved)
    require(saved.get('context_files') == build['context_files'])
    actual=compiler.inspect_image(call,build)
    result.update(image_id=actual['Id'],config_digest=CONFIG,descriptor=actual['Descriptor'],
        rootfs=actual['RootFS'],tag=build['tag'],reservation=RESERVATION,context=CTX,
        context_files=build['context_files'],build_receipt=DRIVER_RECEIPT,
        build_receipt_sha256=DRIVER_SHA,source_pins=dict(compiler.NEW_PINS),container_created=False)
    return actual


def export(api,pins,call,raws,build,result):
    compiler,refresh=modules()
    actual=identity(api,pins,call,build,result)
    raw=refresh.pin_bytes(ROOT,pins,api,IDENTITY)
    saved=refresh.document(raw)
    require(saved.get('schema') == 1 and type(saved.get('schema')) is int
        and saved.get('scope') == SCOPE and saved.get('stage') == 'identity'
        and saved.get('status') == 'VERIFIED' and saved.get('completed') is True
        and saved.get('pins_closed') is True and saved.get('image_id') == actual['Id']
        and saved.get('descriptor') == actual['Descriptor'] and saved.get('rootfs') == actual['RootFS']
        and saved.get('config_digest') == CONFIG and saved.get('failed_parent_sha256') == FAILED_SHA
        and saved.get('driver_receipt_sha256') == DRIVER_SHA
        and saved.get('source_pins') == compiler.NEW_PINS and saved.get('native_eligible') is False
        and saved.get('private_input_allowed') is False and saved.get('control_state_modified') is False
        and 'failure_code' not in saved and 'exception_class' not in saved,'IDENTITY_REFUSED')
    exporter=compiler.load_fixed('ai/state/private-scanner-export.py',raws['ai/state/private-scanner-export.py'])['Exporter']
    owned=exporter(actual['Id'],'compiler')
    result.update(export_receipt=owned.receipt.relative_to(ROOT).as_posix(),
        directory=owned.directory.relative_to(ROOT).as_posix(),identity_sha256=compiler.digest(raw))
    with owned:
        for path in compiler.EXPORT_PATHS:require(owned.copy(path) is not None,'EXPORT_MISSING')
    require(owned.cleaned is True and owned.cli_uncertain is False and len(owned.rows) == 10,
            'EXPORT_CLEANUP_UNCONFIRMED')
    result.update(files=owned.rows,original_id=owned.cid,never_started=True,original_id_absent_verified=True)


def execute(stage):
    require(stage in ('readback','identity','export'),'STAGE_REFUSED')
    compiler,refresh=modules()
    result={'schema':1,'scope':SCOPE,'stage':stage,'status':'REFUSED','completed':False,
        'pins_closed':False,'native_eligible':False,'private_input_allowed':False,
        'control_state_modified':False,'failed_parent_retained_refused':True,
        'failed_parent_sha256':FAILED_SHA,'driver_receipt':DRIVER_RECEIPT,'driver_receipt_sha256':DRIVER_SHA}
    receipt=refresh.Receipt(ROOT/{'readback':READBACK,'identity':IDENTITY,'export':EXPORT}[stage],result)
    failure=None; started=time.monotonic()
    try:
        with compiler.checked_inputs() as (api,pins,call,raws):
            refresh.pin_bytes(ROOT,pins,api,'infra/evidence_interpreter_compile.py',expected=COMPILER_SOURCE_SHA)
            build=fixed_build(api,pins)
            reconstructed_context(api,pins,build)
            resume=compiler.load_fixed('ai/state/private-scanner-resume-pcre.py',raws['ai/state/private-scanner-resume-pcre.py'])
            postflight=resume['live_postflight_module'](api,pins)
            with postflight['observe']() as builder:
                original=compiler.live_originals(call)
                original.consume();builder.consume()
                _,old,_,_=compiler.modules()
                require(builder.result['engine_sha256'] == old.ENGINE,'BUILDER_ENGINE_CHANGED')
                result['builder_engine_sha256']=builder.result['engine_sha256']
                if stage == 'readback':
                    result.update(context=CTX,context_files=build['context_files'],config_digest=CONFIG,
                        source_pins=dict(compiler.NEW_PINS))
                elif stage == 'identity':identity(api,pins,call,build,result)
                else:export(api,pins,call,raws,build,result)
            compiler.live_originals(call).consume()
        result['pins_closed']=True
        require(time.monotonic()-started < (300 if stage != 'export' else 900),'FINAL_DEADLINE')
        result.update(status='VERIFIED',completed=True)
    except BaseException as error:
        failure=error
        result.update(status='REFUSED',completed=False,failure_code='INTERPRETER_READBACK_REFUSED')
    finally:
        result['total_seconds']=round(time.monotonic()-started,3)
        try:receipt.save(result);receipt.close()
        except BaseException:
            result.update(status='REFUSED',completed=False,failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            try:
                if not receipt.stream.closed:receipt.save(result)
            finally:receipt.close()
            raise RuntimeError('RECEIPT_CLOSE_UNCONFIRMED') from None
    require(failure is None)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=('readback','identity','export'))
    result=execute(parser.parse_args(argv).stage)
    print(json.dumps({'stage':result['stage'],'status':result['status'],'native_eligible':False}),flush=True)


if __name__ == '__main__':main()
