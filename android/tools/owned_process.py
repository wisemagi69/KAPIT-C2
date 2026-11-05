"""Windows child-tree ownership, assigned before the child can create descendants."""
import ctypes
from ctypes import wintypes
import os


class OwnedProcessTree:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("This emulator runner currently supports Windows only")

        class Limits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t),
                ("max_working", ctypes.c_size_t), ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]

        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class Extended(ctypes.Structure):
            _fields_ = [("basic", Limits), ("io", Counters), ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.job = self.api.CreateJobObjectW(None, None)
        limits = Extended()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.job or not self.api.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise RuntimeError("Emulator process-tree ownership unavailable")

    def attach_and_resume(self, process):
        if not self.api.AssignProcessToJobObject(self.job, int(process._handle)):
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("Emulator process-tree attachment failed")

        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                ("id", wintypes.DWORD), ("owner", wintypes.DWORD),
                ("base_priority", wintypes.LONG), ("delta_priority", wintypes.LONG), ("flags", wintypes.DWORD)]

        self.api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.api.Thread32First.argtypes = self.api.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        self.api.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenThread.restype = wintypes.HANDLE
        self.api.ResumeThread.argtypes = [wintypes.HANDLE]
        self.api.ResumeThread.restype = wintypes.DWORD
        self.api.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
        self.api.GetProcessIdOfThread.restype = wintypes.DWORD
        snapshot = self.api.CreateToolhelp32Snapshot(0x4, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            raise RuntimeError("Owned suspended emulator thread unavailable")
        matches = []
        try:
            entry = ThreadEntry(size=ctypes.sizeof(ThreadEntry))
            found = self.api.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.owner == process.pid:
                    matches.append(entry.id)
                found = self.api.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            self.api.CloseHandle(snapshot)
        if len(matches) != 1 or process.poll() is not None:
            raise RuntimeError("Owned suspended emulator thread identity mismatch")
        thread = self.api.OpenThread(0x2 | 0x800, False, matches[0])
        if not thread:
            raise RuntimeError("Owned suspended emulator thread cannot be opened")
        try:
            if self.api.GetProcessIdOfThread(thread) != process.pid or process.poll() is not None:
                raise RuntimeError("Owned emulator identity changed before resume")
            if self.api.ResumeThread(thread) != 1:
                raise RuntimeError("Owned emulator thread did not resume")
        finally:
            self.api.CloseHandle(thread)

    def close(self):
        if self.job:
            if not self.api.CloseHandle(self.job):
                raise RuntimeError("Owned emulator process-tree cleanup failed")
            self.job = None
