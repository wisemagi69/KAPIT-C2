"""Windows LPAC/job capability probes. Evidence validation stays quota-gated CLOSED."""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
AREA = ROOT / '.cache/m1-runtime/evidence-tools/isolation'
MEMORY = 128 * 1024 * 1024
CPU_TICKS = 10_000_000
OUTPUT = 4096
LIMIT_FLAGS = 0x2000 | 0x8 | 0x100 | 0x200 | 0x2 | 0x4
CREATE_FLAGS = 0x4 | 0x80000 | 0x400 | 0x08000000  # suspended, extended, unicode, no-window


class IsolationError(RuntimeError):
    pass


def fail(code):
    raise IsolationError(code)


def path_checked(path):
    path = Path(path)
    try:
        parts = path.relative_to(ROOT).parts
    except ValueError:
        fail('PATH_REFUSED')
    current = ROOT
    for part in ('', *parts):
        if part in {'.', '..'}:
            fail('PATH_REFUSED')
        if part:
            current = current / part
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                fail('PATH_REFUSED')
    if path.resolve() != path:
        fail('PATH_REFUSED')
    return path


class IO_COUNTERS(c.Structure):
    _fields_ = [(n, c.c_ulonglong) for n in ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                                           'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class BASIC_LIMIT(c.Structure):
    _fields_ = [('ProcessTime', c.c_longlong), ('JobTime', c.c_longlong), ('Flags', w.DWORD),
                ('MinimumWorkingSet', c.c_size_t), ('MaximumWorkingSet', c.c_size_t), ('ActiveProcesses', w.DWORD),
                ('Affinity', c.c_size_t), ('Priority', w.DWORD), ('Scheduling', w.DWORD)]


class EXTENDED_LIMIT(c.Structure):
    _fields_ = [('Basic', BASIC_LIMIT), ('Io', IO_COUNTERS), ('ProcessMemory', c.c_size_t),
                ('JobMemory', c.c_size_t), ('PeakProcessMemory', c.c_size_t), ('PeakJobMemory', c.c_size_t)]


class ACCOUNTING(c.Structure):
    _fields_ = [('UserTime', c.c_longlong), ('KernelTime', c.c_longlong), ('PeriodUserTime', c.c_longlong),
                ('PeriodKernelTime', c.c_longlong), ('PageFaults', w.DWORD), ('TotalProcesses', w.DWORD),
                ('ActiveProcesses', w.DWORD), ('TerminatedProcesses', w.DWORD)]


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [('Length', w.DWORD), ('Descriptor', c.c_void_p), ('Inherit', w.BOOL)]


class SECURITY_CAPABILITIES(c.Structure):
    _fields_ = [('Sid', c.c_void_p), ('Capabilities', c.c_void_p), ('Count', w.DWORD), ('Reserved', w.DWORD)]


class STARTUPINFO(c.Structure):
    _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR), ('title', w.LPWSTR),
                ('x', w.DWORD), ('y', w.DWORD), ('xsize', w.DWORD), ('ysize', w.DWORD),
                ('xchars', w.DWORD), ('ychars', w.DWORD), ('fill', w.DWORD), ('flags', w.DWORD),
                ('show', w.WORD), ('reserved2size', w.WORD), ('reserved2', c.c_void_p),
                ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]


class STARTUPINFOEX(c.Structure):
    _fields_ = [('startup', STARTUPINFO), ('attributes', c.c_void_p)]


class PROCESS_INFORMATION(c.Structure):
    _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]


def job_limits():
    value = EXTENDED_LIMIT()
    value.Basic.Flags = LIMIT_FLAGS
    value.Basic.ActiveProcesses = 1
    value.Basic.ProcessTime = CPU_TICKS
    value.Basic.JobTime = CPU_TICKS
    value.ProcessMemory = MEMORY
    value.JobMemory = MEMORY
    return value


class Windows:
    """Explicit ctypes signatures; no profile creation, global ACL or token adoption."""
    def __init__(self):
        if os.name != 'nt':
            fail('WINDOWS_UNAVAILABLE')
        self.k = c.WinDLL('kernel32', use_last_error=True)
        self.a = c.WinDLL('advapi32', use_last_error=True)
        self.u = c.WinDLL('userenv', use_last_error=True)
        self.ole = c.WinDLL('ole32', use_last_error=True)
        self._bind(self.k, 'GetCurrentProcess', [], w.HANDLE)
        self._bind(self.k, 'CloseHandle', [w.HANDLE], w.BOOL)
        self._bind(self.k, 'LocalFree', [c.c_void_p], c.c_void_p)
        self._bind(self.a, 'FreeSid', [c.c_void_p], c.c_void_p)
        self._bind(self.u, 'DeriveAppContainerSidFromAppContainerName', [w.LPCWSTR, c.POINTER(c.c_void_p)], c.c_long)
        self._bind(self.u, 'GetAppContainerFolderPath', [w.LPCWSTR, c.POINTER(w.LPWSTR)], c.c_long)
        self._bind(self.ole, 'CoTaskMemFree', [c.c_void_p], None)
        self._bind(self.a, 'OpenProcessToken', [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL)
        self._bind(self.a, 'GetTokenInformation', [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
        self._bind(self.a, 'ConvertSidToStringSidW', [c.c_void_p, c.POINTER(w.LPWSTR)], w.BOOL)
        self._bind(self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p], w.BOOL)
        self._bind(self.a, 'SetFileSecurityW', [w.LPCWSTR, w.DWORD, c.c_void_p], w.BOOL)
        self._bind(self.a, 'GetNamedSecurityInfoW', [w.LPWSTR, c.c_int, w.DWORD, c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p)], w.DWORD)
        self._bind(self.a, 'GetSecurityDescriptorControl', [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)], w.BOOL)
        self._bind(self.a, 'GetAce', [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)], w.BOOL)
        self._bind(self.k, 'CreateJobObjectW', [c.c_void_p, w.LPCWSTR], w.HANDLE)
        self._bind(self.k, 'SetInformationJobObject', [w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL)
        self._bind(self.k, 'QueryInformationJobObject', [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL)
        self._bind(self.k, 'AssignProcessToJobObject', [w.HANDLE, w.HANDLE], w.BOOL)
        self._bind(self.k, 'TerminateJobObject', [w.HANDLE, w.UINT], w.BOOL)
        self._bind(self.k, 'TerminateProcess', [w.HANDLE, w.UINT], w.BOOL)
        self._bind(self.k, 'ResumeThread', [w.HANDLE], w.DWORD)
        self._bind(self.k, 'WaitForSingleObject', [w.HANDLE, w.DWORD], w.DWORD)
        self._bind(self.k, 'GetExitCodeProcess', [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL)
        self._bind(self.k, 'CreateEventW', [c.POINTER(SECURITY_ATTRIBUTES), w.BOOL, w.BOOL, w.LPCWSTR], w.HANDLE)
        self._bind(self.k, 'CreatePipe', [c.POINTER(w.HANDLE), c.POINTER(w.HANDLE), c.POINTER(SECURITY_ATTRIBUTES), w.DWORD], w.BOOL)
        self._bind(self.k, 'SetHandleInformation', [w.HANDLE, w.DWORD, w.DWORD], w.BOOL)
        self._bind(self.k, 'PeekNamedPipe', [w.HANDLE, c.c_void_p, w.DWORD, c.c_void_p, c.POINTER(w.DWORD), c.c_void_p], w.BOOL)
        self._bind(self.k, 'ReadFile', [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL)
        self._bind(self.k, 'InitializeProcThreadAttributeList', [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL)
        self._bind(self.k, 'UpdateProcThreadAttribute', [c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL)
        self._bind(self.k, 'DeleteProcThreadAttributeList', [c.c_void_p], None)
        self._bind(self.k, 'CreateProcessW', [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                           c.c_void_p, w.LPCWSTR, c.POINTER(STARTUPINFOEX), c.POINTER(PROCESS_INFORMATION)], w.BOOL)

    @staticmethod
    def _bind(dll, name, args, returns):
        function = getattr(dll, name)
        function.argtypes, function.restype = args, returns

    @staticmethod
    def require(value, code):
        if not value:
            fail(code)

    def close(self, handle):
        if handle:
            self.k.CloseHandle(handle)

    def sid_text(self, sid):
        text = w.LPWSTR()
        self.require(self.a.ConvertSidToStringSidW(sid, c.byref(text)), 'SID_UNAVAILABLE')
        try:
            return text.value
        finally:
            self.k.LocalFree(c.cast(text, c.c_void_p))

    def token_info(self, process, kind):
        token = w.HANDLE()
        self.require(self.a.OpenProcessToken(process, 8, c.byref(token)), 'TOKEN_UNAVAILABLE')
        try:
            size = w.DWORD()
            self.a.GetTokenInformation(token, kind, None, 0, c.byref(size))
            if not 0 < size.value < 65536:
                fail('TOKEN_UNAVAILABLE')
            buffer = c.create_string_buffer(size.value)
            self.require(self.a.GetTokenInformation(token, kind, buffer, size, c.byref(size)), 'TOKEN_UNAVAILABLE')
            return buffer
        finally:
            self.close(token)

    def fresh_sid(self):
        sid = c.c_void_p()
        if self.u.DeriveAppContainerSidFromAppContainerName('Kapit.Evidence.' + uuid.uuid4().hex, c.byref(sid)) != 0 or not sid.value:
            fail('SID_DERIVATION_UNAVAILABLE')
        return sid

    def current_user(self):
        data = self.token_info(self.k.GetCurrentProcess(), 1)
        return self.sid_text(c.c_void_p.from_buffer(data).value)

    def require_profile(self, sid):
        """Read-only prerequisite check; no profile adoption or registration.

        Fresh derive-only identities do not provision a profile on this host.
        Even an unexpectedly present profile needs separate ownership/provisioning
        proof, which the current scoped helper deliberately cannot manufacture.
        """
        folder = w.LPWSTR()
        try:
            status = self.u.GetAppContainerFolderPath(self.sid_text(sid), c.byref(folder))
            if status != 0 or not folder:
                fail('APPCONTAINER_PROFILE_UNAVAILABLE')
            fail('APPCONTAINER_PROFILE_OWNERSHIP_UNVERIFIED')
        finally:
            if folder:
                self.ole.CoTaskMemFree(c.cast(folder, c.c_void_p))

    def acl(self, folder, user, app=None, writable=False):
        path_checked(folder)
        entries = [('S-1-5-18', 0x1f01ff), (user, 0x1f01ff)]
        if app:
            entries.append((app, 0x1f01ff if writable else 0x1200a9))
        sddl = 'D:P' + ''.join(f'(A;OICI;0x{mask:x};;;{sid})' for sid, mask in entries)
        descriptor = c.c_void_p()
        self.require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(descriptor), None), 'ACL_UNAVAILABLE')
        try:
            self.require(self.a.SetFileSecurityW(str(folder), 0x80000004, descriptor), 'ACL_UNAVAILABLE')
        finally:
            self.k.LocalFree(descriptor)
        self.verify_acl(folder, entries)

    def verify_acl(self, folder, entries):
        dacl, descriptor = c.c_void_p(), c.c_void_p()
        if self.a.GetNamedSecurityInfoW(str(path_checked(folder)), 1, 4, None, None, c.byref(dacl), None, c.byref(descriptor)) != 0:
            fail('ACL_UNVERIFIED')
        try:
            control, revision = w.WORD(), w.DWORD()
            self.require(self.a.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)), 'ACL_UNVERIFIED')
            if not control.value & 0x1000 or not dacl.value:
                fail('ACL_UNVERIFIED')
            count = c.c_ushort.from_address(dacl.value + 4).value
            actual = []
            for index in range(count):
                ace = c.c_void_p()
                self.require(self.a.GetAce(dacl, index, c.byref(ace)), 'ACL_UNVERIFIED')
                if c.c_ubyte.from_address(ace.value).value != 0 or c.c_ubyte.from_address(ace.value + 1).value != 3:
                    fail('ACL_UNVERIFIED')
                actual.append((self.sid_text(ace.value + 8), w.DWORD.from_address(ace.value + 4).value))
            if actual != entries:
                fail('ACL_UNVERIFIED')
        finally:
            self.k.LocalFree(descriptor)

    def job(self):
        job = self.k.CreateJobObjectW(None, None)
        self.require(job, 'JOB_UNAVAILABLE')
        try:
            limits = job_limits()
            self.require(self.k.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)), 'JOB_UNAVAILABLE')
            observed = EXTENDED_LIMIT()
            self.require(self.k.QueryInformationJobObject(job, 9, c.byref(observed), c.sizeof(observed), None), 'JOB_UNVERIFIED')
            if (observed.Basic.Flags != LIMIT_FLAGS or observed.Basic.ActiveProcesses != 1
                    or observed.Basic.ProcessTime != CPU_TICKS or observed.Basic.JobTime != CPU_TICKS
                    or observed.ProcessMemory != MEMORY or observed.JobMemory != MEMORY):
                fail('JOB_UNVERIFIED')
            return job
        except Exception:
            self.close(job)
            raise

    def token_proof(self, process, sid):
        if (w.DWORD.from_buffer(self.token_info(process, 29)).value != 1
                or w.DWORD.from_buffer(self.token_info(process, 46)).value != 1
                or w.DWORD.from_buffer(self.token_info(process, 30)).value != 0):
            fail('LPAC_UNVERIFIED')
        actual = self.token_info(process, 31)
        if self.sid_text(c.c_void_p.from_buffer(actual).value) != self.sid_text(sid):
            fail('LPAC_UNVERIFIED')


def capability_probe():
    """Actual derive/job API checks only; no child, global profile or validator."""
    result = {'validation': 'CLOSED', 'validators_launched': 0, 'disk_quota': 'UNAVAILABLE',
              'lpac_child': 'NOT_PROBED', 'network': 'NOT_PROBED', 'filesystem': 'NOT_PROBED', 'handles': 'NOT_PROBED'}
    api, sid, job = None, None, None
    try:
        api = Windows()
        sid = api.fresh_sid()
        job = api.job()
        result.update({'status': 'PARTIAL', 'code': 'QUOTA_UNAVAILABLE', 'derive_sid': 'VERIFIED', 'job_configuration': 'VERIFIED'})
        api.require_profile(sid)
    except IsolationError as error:
        result.update({'status': 'UNAVAILABLE', 'code': str(error)})
    except Exception:
        result.update({'status': 'UNAVAILABLE', 'code': 'WINDOWS_CAPABILITY_UNAVAILABLE'})
    finally:
        if api:
            api.close(job)
            if sid:
                api.a.FreeSid(sid)
    return result


def run_isolated(*args, **kwargs):
    """No quota provider exists: never start a validator or accept caller proof."""
    return {'status': 'UNAVAILABLE', 'code': 'QUOTA_UNAVAILABLE', 'validation': 'CLOSED', 'validators_launched': 0}


# Fixed benign, non-image probe. It reads no source/evidence/configuration.
PROBE_SOURCE = r'''
using System; using System.IO; using System.Runtime.InteropServices; using System.Threading;
class Probe {
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateFile(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetHandleInformation(IntPtr h,out uint f);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr p,UIntPtr n,uint a,uint f);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,string cmd,IntPtr p,IntPtr t,bool inherit,uint flags,IntPtr env,string cwd,ref SI si,out PI pi);
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI { public uint cb; public string r,d,t; public uint x,y,xs,ys,xc,yc,fill,flags; public ushort show,res; public IntPtr rp,stdin,stdout,stderr; }
 [StructLayout(LayoutKind.Sequential)] struct PI {public IntPtr process,thread;public uint pid,tid;}
 [DllImport("ws2_32.dll")] static extern int WSAStartup(ushort v,IntPtr data);
 [DllImport("ws2_32.dll")] static extern int WSAGetLastError();
 [DllImport("ws2_32.dll")] static extern UIntPtr socket(int af,int type,int protocol);
 [DllImport("ws2_32.dll")] static extern int connect(UIntPtr s,byte[] addr,int size);
 [DllImport("ws2_32.dll")] static extern int closesocket(UIntPtr s);
 [DllImport("ws2_32.dll")] static extern int WSACleanup();
 static bool DeniedFile(string path,uint access,uint disposition) {IntPtr h=CreateFile(path,access,0,IntPtr.Zero,disposition,0,IntPtr.Zero);if(h.ToInt64()!=-1){CloseHandle(h);return false;}return Marshal.GetLastWin32Error()==5;}
 static bool NetworkDenied(byte[] ip,int port) { UIntPtr s=socket(2,1,6);if(s.ToUInt64()==UInt64.MaxValue)return WSAGetLastError()==10013; byte[] a=new byte[16];a[0]=2;a[2]=(byte)(port>>8);a[3]=(byte)port;Array.Copy(ip,0,a,4,4);int r=connect(s,a,16);int error=WSAGetLastError();closesocket(s);return r==-1 && error==10013; }
 static int Main(string[] a) {try {
  if(a[0]=="cpu"){long x=0;while(true){x++;}}
  if(a[0]=="wall"){Thread.Sleep(60000);return 2;}
  if(a[0]=="output"){while(true)Console.Write(new string('X',1024));}
  if(a[0]=="memory"){bool denied=VirtualAlloc(IntPtr.Zero,new UIntPtr(256UL*1024*1024),0x3000,4)==IntPtr.Zero;Console.WriteLine(denied?"MEMORY_DENIED":"MEMORY_ALLOWED");return denied?0:2;}
  bool file=DeniedFile(a[1],0x80000000,3);bool tool=DeniedFile(a[2],0x40000000,1);
  File.WriteAllBytes(Path.Combine(a[3],"synthetic.bin"),new byte[]{1,2,3,4});
  bool scratch=new FileInfo(Path.Combine(a[3],"synthetic.bin")).Length==4;
  uint flags;bool handle=!GetHandleInformation(new IntPtr(Int64.Parse(a[4])),out flags) && Marshal.GetLastWin32Error()==6;
  IntPtr data=Marshal.AllocHGlobal(1024);bool network=false;try{if(WSAStartup(0x202,data)==0){network=NetworkDenied(new byte[]{127,0,0,1},Int32.Parse(a[5])) && NetworkDenied(new byte[]{192,0,2,1},9);WSACleanup();}}finally{Marshal.FreeHGlobal(data);}
  SI si=new SI();si.cb=(uint)Marshal.SizeOf(si);PI pi;
  bool child=!CreateProcess(a[6],"cmd.exe /d /c exit 0",IntPtr.Zero,IntPtr.Zero,false,0x08000000,IntPtr.Zero,a[3],ref si,out pi);
  bool escape=!CreateProcess(a[6],"cmd.exe /d /c exit 0",IntPtr.Zero,IntPtr.Zero,false,0x09000000,IntPtr.Zero,a[3],ref si,out pi);
  if(file&&tool&&scratch&&handle&&network&&child&&escape){Console.WriteLine("BASELINE_DENIALS_VERIFIED");return 0;}Console.WriteLine("BASELINE_DENIAL_UNCONFIRMED");return 2;
 }catch{Console.WriteLine("PROBE_UNAVAILABLE");return 3;}}
}
'''


def _probe_environment(folder):
    windows = Path(os.environ.get('SystemRoot', 'C:/Windows'))
    return {'SystemRoot': str(windows), 'WINDIR': str(windows), 'PATH': str(windows / 'System32'),
            'TEMP': str(folder), 'TMP': str(folder), 'USERPROFILE': str(folder), 'APPDATA': str(folder),
            'LOCALAPPDATA': str(folder), 'HOME': str(folder), 'COMPLUS_EnableDiagnostics': '0'}


def _stop_owned(api, process, job, assigned):
    """Only freshly returned owned handles; uncertainty must dominate prior errors."""
    if not process.process:
        return
    try:
        state = api.k.WaitForSingleObject(process.process, 0)
        if state != 0:
            # WAIT_FAILED is unknown ownership/control state; still attempt only
            # our returned process/job handles, never look up or kill a PID.
            stopped = (api.k.TerminateJobObject(job, 72) if assigned
                       else api.k.TerminateProcess(process.process, 72))
            if not stopped:
                fail('OWNED_CHILD_STOP_UNCONFIRMED')
        if api.k.WaitForSingleObject(process.process, 5000) != 0:
            fail('OWNED_CHILD_STOP_UNCONFIRMED')
        exit_code = w.DWORD()
        if not api.k.GetExitCodeProcess(process.process, c.byref(exit_code)) or exit_code.value == 259:
            fail('OWNED_CHILD_STOP_UNCONFIRMED')
        if assigned:
            accounting = ACCOUNTING()
            if (not api.k.QueryInformationJobObject(job, 1, c.byref(accounting), c.sizeof(accounting), None)
                    or accounting.ActiveProcesses != 0):
                fail('OWNED_CHILD_STOP_UNCONFIRMED')
    except Exception:
        fail('OWNED_CHILD_STOP_UNCONFIRMED')


def _launch_probe(api, exe, digest, sid, args, cwd, event, mode):
    """Only the owned fixed probe executable; no generic caller command surface."""
    raw = path_checked(exe).read_bytes()
    if not raw or hashlib.sha256(raw).hexdigest() != digest:
        fail('PROBE_BINARY_CHANGED')
    if mode not in {'baseline', 'memory', 'cpu', 'wall', 'output'}:
        fail('PROBE_MODE_REFUSED')
    handles, attributes, initialized = [], None, False
    process = PROCESS_INFORMATION()
    job, assigned = api.job(), False
    try:
        security = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), None, True)
        read, write = w.HANDLE(), w.HANDLE()
        api.require(api.k.CreatePipe(c.byref(read), c.byref(write), c.byref(security), 4096), 'PIPE_UNAVAILABLE')
        handles.extend([read, write])
        api.require(api.k.SetHandleInformation(read, 1, 0), 'PIPE_UNAVAILABLE')
        stdin_read, stdin_write = w.HANDLE(), w.HANDLE()
        api.require(api.k.CreatePipe(c.byref(stdin_read), c.byref(stdin_write), c.byref(security), 4096), 'PIPE_UNAVAILABLE')
        handles.extend([stdin_read, stdin_write])
        api.require(api.k.SetHandleInformation(stdin_write, 1, 0), 'PIPE_UNAVAILABLE')
        size = c.c_size_t()
        api.k.InitializeProcThreadAttributeList(None, 3, 0, c.byref(size))
        attributes = c.create_string_buffer(size.value)
        api.require(api.k.InitializeProcThreadAttributeList(attributes, 3, 0, c.byref(size)), 'LPAC_ATTRIBUTES_UNAVAILABLE')
        initialized = True
        caps = SECURITY_CAPABILITIES(sid, None, 0, 0)
        allowed = (w.HANDLE * 2)(stdin_read.value, write.value)
        optout = w.DWORD(1)
        for key, value in ((0x20009, caps), (0x20002, allowed), (0x2000f, optout)):
            api.require(api.k.UpdateProcThreadAttribute(attributes, 0, key, c.byref(value), c.sizeof(value), None, None), 'LPAC_ATTRIBUTES_UNAVAILABLE')
        start = STARTUPINFOEX()
        start.startup.cb = c.sizeof(start)
        start.startup.flags = 0x100
        start.startup.stdin, start.startup.stdout, start.startup.stderr = stdin_read.value, write.value, write.value
        start.attributes = c.cast(attributes, c.c_void_p)
        environment = c.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(_probe_environment(cwd).items())) + '\0\0')
        command = c.create_unicode_buffer(subprocess.list2cmdline([str(exe), mode, *args]))
        created = api.k.CreateProcessW(str(exe), command, None, None, True, CREATE_FLAGS,
                    environment, str(cwd), c.byref(start), c.byref(process))
        if not created:
            fail({5: 'LPAC_PROCESS_ACCESS_DENIED', 1314: 'LPAC_PROCESS_PRIVILEGE_UNAVAILABLE',
                  50: 'LPAC_PROCESS_NOT_SUPPORTED', 87: 'LPAC_PROCESS_INVALID_PARAMETER'}.get(c.get_last_error(), 'LPAC_PROCESS_UNAVAILABLE'))
        api.token_proof(process.process, sid)
        api.require(api.k.AssignProcessToJobObject(job, process.process), 'JOB_ASSIGNMENT_UNAVAILABLE')
        assigned = True
        # No child instruction runs before token proof and kernel job assignment.
        if api.k.ResumeThread(process.thread) == 0xffffffff:
            fail('RESUME_UNAVAILABLE')
        api.close(write); handles.remove(write)
        api.close(stdin_read); handles.remove(stdin_read)
        api.close(stdin_write); handles.remove(stdin_write)  # Child stdin gets EOF.
        deadline = time.monotonic() + (1 if mode == 'wall' else 12)
        output = bytearray()
        reason = 'EXITED'
        while True:
            available = w.DWORD()
            if api.k.PeekNamedPipe(read, None, 0, None, c.byref(available), None) and available.value:
                amount = min(available.value, OUTPUT + 1 - len(output))
                buffer = c.create_string_buffer(amount)
                got = w.DWORD()
                api.require(api.k.ReadFile(read, buffer, amount, c.byref(got), None), 'PIPE_UNAVAILABLE')
                output.extend(buffer.raw[:got.value])
                if len(output) > OUTPUT:
                    reason = 'OUTPUT_LIMIT'
                    break
            if api.k.WaitForSingleObject(process.process, 0) == 0:
                break
            if time.monotonic() >= deadline:
                reason = 'WALL_LIMIT'
                break
            time.sleep(0.01)
        if reason != 'EXITED':
            api.require(api.k.TerminateJobObject(job, 71), 'JOB_TERMINATION_UNAVAILABLE')
        if api.k.WaitForSingleObject(process.process, 5000) != 0:
            fail('OWNED_CHILD_STOP_UNCONFIRMED')
        accounting = ACCOUNTING()
        api.require(api.k.QueryInformationJobObject(job, 1, c.byref(accounting), c.sizeof(accounting), None), 'JOB_UNVERIFIED')
        if accounting.ActiveProcesses != 0:
            fail('OWNED_CHILD_STOP_UNCONFIRMED')
        exit_code = w.DWORD()
        api.require(api.k.GetExitCodeProcess(process.process, c.byref(exit_code)), 'PROBE_UNAVAILABLE')
        # Output is compared internally; never return arbitrary child text.
        return reason, bytes(output), exit_code.value, accounting.UserTime
    finally:
        try:
            _stop_owned(api, process, job, assigned)
        finally:
            # These handles came only from this invocation; close even on an
            # unconfirmed stop, preserving failure instead of claiming cleanup.
            api.close(process.thread); api.close(process.process)
            if initialized:
                api.k.DeleteProcThreadAttributeList(attributes)
            for handle in handles:
                api.close(handle)
            api.close(job)  # KILL_ON_JOB_CLOSE; never a substitute for stop proof.


def benign_probe():
    """Opt-in actual OS denials using only a fixed four-byte synthetic scratch file."""
    api, sid, event, listener, run = None, None, None, None, None
    result = {'validation': 'CLOSED', 'validators_launched': 0, 'disk_quota': 'UNAVAILABLE',
              'validation_receipt': 'NONE', 'benign_probes_completed': 0}
    try:
        api = Windows()
        sid = api.fresh_sid()
        # Refuse before scratch/compiler/listener/child work when the required
        # OS identity/profile has not been separately provisioned and verified.
        api.require_profile(sid)
        app, user = api.sid_text(sid), api.current_user()
        path_checked(AREA).mkdir(parents=True, exist_ok=True)
        run = path_checked(AREA / uuid.uuid4().hex)
        run.mkdir()
        api.acl(run, user)
        tools, scratch, protected = [run / name for name in ('tools', 'scratch', 'protected')]
        for directory in (tools, scratch, protected):
            directory.mkdir()
        api.acl(tools, user, app, False)
        api.acl(scratch, user, app, True)
        api.acl(protected, user)
        canary = protected / 'synthetic-canary.bin'
        canary.write_bytes(b'fixed-synthetic-canary')
        source, exe = tools / 'probe.cs', tools / 'probe.exe'
        source.write_text(PROBE_SOURCE, encoding='utf-8')
        compiler = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if not compiler.is_file():
            fail('PROBE_COMPILER_UNAVAILABLE')
        try:
            built = subprocess.run([str(compiler), '/nologo', '/noconfig', '/target:exe', '/platform:x64',
                        '/out:' + str(exe), str(source)], cwd=tools, env=_probe_environment(scratch),
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=30, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired):
            fail('PROBE_COMPILER_UNAVAILABLE')
        if built.returncode != 0 or not exe.is_file():
            fail('PROBE_COMPILATION_UNAVAILABLE')
        digest = hashlib.sha256(path_checked(exe).read_bytes()).hexdigest()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
        except OSError:
            fail('PROBE_LISTENER_UNAVAILABLE')
        security = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), None, True)
        event = api.k.CreateEventW(c.byref(security), True, False, None)
        api.require(event, 'PROBE_HANDLE_UNAVAILABLE')
        args = [str(canary), str(tools / 'forbidden-write.bin'), str(scratch), str(event),
                str(listener.getsockname()[1]), str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/cmd.exe')]
        expected = {'baseline': b'BASELINE_DENIALS_VERIFIED\r\n', 'memory': b'MEMORY_DENIED\r\n'}
        for mode in ('baseline', 'memory', 'cpu', 'wall', 'output'):
            reason, output, code, ticks = _launch_probe(api, exe, digest, sid, args, scratch, event, mode)
            passed = ((mode in expected and reason == 'EXITED' and code == 0 and output == expected[mode])
                      or (mode == 'cpu' and reason == 'EXITED' and code != 0 and ticks >= CPU_TICKS)
                      or (mode == 'wall' and reason == 'WALL_LIMIT')
                      or (mode == 'output' and reason == 'OUTPUT_LIMIT'))
            if not passed:
                fail('BENIGN_' + mode.upper() + '_UNCONFIRMED')
            result['benign_probes_completed'] += 1
        result.update({'status': 'BENIGN_CONTROLS_PROBED', 'code': 'QUOTA_UNAVAILABLE',
                       'lpac_child': 'VERIFIED', 'network': 'DENIED', 'protected_read': 'DENIED',
                       'tool_write': 'DENIED', 'scratch_write': 'VERIFIED', 'unexpected_handle': 'DENIED',
                       'child_and_breakaway': 'DENIED', 'memory_cpu_wall_output': 'VERIFIED'})
    except IsolationError as error:
        result.update({'status': 'UNAVAILABLE', 'code': str(error)})
    except Exception:
        result.update({'status': 'UNAVAILABLE', 'code': 'WINDOWS_PROBE_UNAVAILABLE'})
    finally:
        if listener:
            listener.close()
        if api:
            api.close(event)
            if sid:
                api.a.FreeSid(sid)
    result['run_id'] = run.name if run else None
    if run:
        (path_checked(run) / 'result.json').write_text(json.dumps(result, sort_keys=True), encoding='ascii')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benign-probe', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = benign_probe() if args.benign_probe else capability_probe()
    except Exception:
        result = {'status': 'UNAVAILABLE', 'code': 'WINDOWS_PROBE_UNAVAILABLE', 'validation': 'CLOSED', 'validators_launched': 0}
    print(json.dumps(result, sort_keys=True))
    return 2  # Quota and validation remain unavailable even when benign probes pass.


if __name__ == '__main__':
    raise SystemExit(main())
