"""Linux/amd64 containment CANDIDATE; no private-input/readiness receipt.

Call only in a fresh, single-threaded, externally quota-limited owned container,
after trusted library initialization and BEFORE reading stdin. Imports are inert.
The trusted supervisor must prove image/mount/namespace/resource/cleanup policy.
Any error requires process termination; there is no unrestricted retry/fallback.
"""
from __future__ import annotations

import ctypes as c
import errno
import os
import platform
import re
import stat
import sys

SCRATCH_BYTES = 64 * 1024 * 1024
SCRATCH_INODES = 128
UID = 65532
O_PATH = 0x200000
O_DIRECTORY = 0x10000
O_NOFOLLOW = 0x20000
O_ACCMODE = 3

# Linux v6.12 UAPI: ABI5 includes REFER(ABI2), TRUNCATE(ABI3),
# TCP(ABI4), IOCTL_DEV(ABI5). Reads remain available for initialized public tools.
FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13
FS_TRUNCATE = 1 << 14
FS_IOCTL_DEV = 1 << 15
HANDLED_FS = sum(1 << bit for bit in (0, 1, *range(4, 16)))
SCRATCH_FS = FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_DIR | FS_MAKE_REG | FS_REFER | FS_TRUNCATE
HANDLED_NET = 3  # BIND_TCP and CONNECT_TCP; no network rule grants either.
ABI3_POLICY_ID = "linux-amd64-landlock3-seccomp-v1"
ABI3_HANDLED_FS = HANDLED_FS & ~FS_IOCTL_DEV

AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
KILL_PROCESS = 0x80000000
ALLOW = 0x7FFF0000
DENY = 0x00050000 | errno.EPERM

# Exact post-initialization allowlist. Everything else, including new syscalls,
# fails EPERM. No exec/clone/fork/socket/ioctl/mount/IPC/handle-open/io_uring,
# memfd/ptrace/process_vm/prctl/seccomp/Landlock mutation is permitted.
SYSCALLS = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5, "lstat": 6,
    "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15, "pread64": 17,
    "pwrite64": 18, "readv": 19, "writev": 20, "access": 21, "select": 23,
    "sched_yield": 24, "mremap": 25, "msync": 26, "mincore": 27, "madvise": 28,
    "nanosleep": 35, "getpid": 39, "exit": 60, "uname": 63, "fcntl": 72,
    "fsync": 74, "fdatasync": 75, "truncate": 76, "ftruncate": 77, "getcwd": 79,
    "chdir": 80, "rename": 82, "mkdir": 83, "rmdir": 84, "unlink": 87, "readlink": 89,
    "gettimeofday": 96, "getrlimit": 97, "getrusage": 98, "sysinfo": 99, "times": 100,
    "getuid": 102, "getgid": 104, "geteuid": 107, "getegid": 108, "getppid": 110,
    "getgroups": 115, "getresuid": 118, "getresgid": 120, "sigaltstack": 131,
    "statfs": 137, "fstatfs": 138, "gettid": 186, "futex": 202, "sched_getaffinity": 204,
    "getdents64": 217, "clock_gettime": 228, "clock_getres": 229, "clock_nanosleep": 230,
    "exit_group": 231, "openat": 257, "mkdirat": 258, "newfstatat": 262,
    "unlinkat": 263, "renameat": 264, "readlinkat": 267, "faccessat": 269,
    "pselect6": 270, "ppoll": 271, "prlimit64": 302, "getrandom": 318,
    "statx": 332, "close_range": 436, "faccessat2": 439,
}


class ConfinementUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("LINUX_CONFINEMENT_UNAVAILABLE")


def require(value):
    if value is not True:
        raise ConfinementUnavailable()


class RulesetAttr(c.Structure):
    _fields_ = [("handled_access_fs", c.c_uint64), ("handled_access_net", c.c_uint64)]


class RulesetAttrAbi3(c.Structure):
    # Explicit filesystem-only policy, not an ABI5 best-effort downgrade.
    _fields_ = [("handled_access_fs", c.c_uint64)]


class PathBeneath(c.Structure):
    _pack_ = 1  # The UAPI explicitly packs this structure (12 bytes, not16).
    _fields_ = [("allowed_access", c.c_uint64), ("parent_fd", c.c_int32)]


class SockFilter(c.Structure):
    _fields_ = [("code", c.c_uint16), ("jt", c.c_uint8), ("jf", c.c_uint8), ("k", c.c_uint32)]


class SockFprog(c.Structure):
    _fields_ = [("len", c.c_uint16), ("filter", c.POINTER(SockFilter))]


class StatFs(c.Structure):
    # Explicit amd64 long widths also make pure layout tests portable on Windows.
    _fields_ = [("type", c.c_int64), ("bsize", c.c_int64), ("blocks", c.c_uint64),
                ("bfree", c.c_uint64), ("bavail", c.c_uint64), ("files", c.c_uint64),
                ("ffree", c.c_uint64), ("fsid", c.c_int32 * 2), ("namelen", c.c_int64),
                ("frsize", c.c_int64), ("flags", c.c_int64), ("spare", c.c_int64 * 4)]


def filter_program():
    """Pure classic-BPF tuples; arch and x32 checks precede syscall matching."""
    program = [(0x20, 0, 0, 4), (0x15, 1, 0, AUDIT_ARCH_X86_64), (0x06, 0, 0, KILL_PROCESS),
               (0x20, 0, 0, 0), (0x45, 0, 1, X32_SYSCALL_BIT), (0x06, 0, 0, KILL_PROCESS)]
    # prlimit64 is readback for self only (pid=0, new_limit=NULL). Check both
    # halves of both 64-bit arguments; a high-half pointer must not bypass it.
    program.append((0x15, 0, 13, SYSCALLS["prlimit64"]))
    for offset in (16, 20, 32, 36):
        program.extend(((0x20, 0, 0, offset), (0x15, 1, 0, 0), (0x06, 0, 0, DENY)))
    program.append((0x06, 0, 0, ALLOW))
    for number in sorted(set(SYSCALLS.values())):
        if number == SYSCALLS["prlimit64"]:
            continue
        program.extend(((0x15, 0, 1, number), (0x06, 0, 0, ALLOW)))
    program.append((0x06, 0, 0, DENY))
    return tuple(program)


def _supported():
    require(sys.platform == "linux" and platform.machine() == "x86_64"
            and sys.byteorder == "little" and c.sizeof(c.c_void_p) == 8
            and c.sizeof(c.c_long) == 8)


def _read(path, limit=65536):
    with open(path, "rb") as source:
        value = source.read(limit + 1)
    require(len(value) <= limit)
    return value.decode("ascii", errors="strict")


def _status(raw):
    items = {}
    for line in raw.splitlines():
        key, _, value = line.partition(":")
        require(key not in items)
        items[key] = value.strip()
    require(items.get("Uid") == "65532\t65532\t65532\t65532"
            and items.get("Gid") == "65532\t65532\t65532\t65532")
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        require(items.get(key) == "0000000000000000")
    require(items.get("Threads") == "1" and items.get("NoNewPrivs") == "1")


def _process():
    require(os.getpid() == 1 and os.getuid() == UID and os.geteuid() == UID
            and os.getgid() == UID and os.getegid() == UID)
    require(os.listdir("/proc/self/task") == [str(os.getpid())])
    require(set(os.getgroups()) <= {UID})
    _status(_read("/proc/self/status"))


def _mounts(raw, device):
    scratch, root = [], []
    for line in raw.splitlines():
        before, separator, after = line.partition(" - ")
        require(bool(separator))
        parts, extra = before.split(), after.split()
        require(len(parts) >= 6 and len(extra) >= 3)
        if parts[4] == "/":
            root.append(parts)
        if parts[4] == "/scratch":
            scratch.append((parts, extra))
    require(len(root) == 1 and "ro" in root[0][5].split(",") and len(scratch) == 1)
    parts, extra = scratch[0]
    require(parts[2] == device and parts[3] == "/" and extra[0] == "tmpfs"
            and {"rw", "noexec", "nosuid", "nodev"} <= set(parts[5].split(",")))


def _scratch(fd, kernel):
    import fcntl
    require(type(fd) is int and fd >= 3)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require(flags & (O_PATH | O_DIRECTORY | O_NOFOLLOW) == O_PATH | O_DIRECTORY | O_NOFOLLOW)
    item = os.fstat(fd)
    require(stat.S_ISDIR(item.st_mode) and stat.S_IMODE(item.st_mode) == 0o700
            and item.st_uid == UID and item.st_gid == UID)
    other = os.open("/scratch", O_PATH | O_DIRECTORY | O_NOFOLLOW | os.O_CLOEXEC)
    try:
        target = os.fstat(other)
        require((target.st_dev, target.st_ino) == (item.st_dev, item.st_ino))
    finally:
        os.close(other)
    kernel.scratch_filesystem(fd)
    volume = os.fstatvfs(fd)
    require(0 < volume.f_frsize * volume.f_blocks <= SCRATCH_BYTES
            and 0 < volume.f_files <= SCRATCH_INODES)
    _mounts(_read("/proc/self/mountinfo"), str(os.major(item.st_dev)) + ":" + str(os.minor(item.st_dev)))


def _descriptors(scratch_fd):
    import fcntl
    names = os.listdir("/proc/self/fd")
    require(all(re.fullmatch(r"[0-9]+", name) is not None for name in names))
    seen = set()
    for name in names:
        fd = int(name)
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            item = os.fstat(fd)
        except OSError as error:
            # listdir's own transient descriptor may have closed already.
            if error.errno == errno.EBADF:
                continue
            raise
        require(fd in {0, 1, 2, scratch_fd})
        seen.add(fd)
        if fd != scratch_fd:
            require(stat.S_ISFIFO(item.st_mode) and re.fullmatch(r"pipe:\[[0-9]+\]", os.readlink("/proc/self/fd/" + name)) is not None)
            require(flags & O_ACCMODE == (os.O_RDONLY if fd == 0 else os.O_WRONLY))
    require(seen == {0, 1, 2, scratch_fd})


class _Kernel:
    def __init__(self):
        self.libc = c.CDLL(None, use_errno=True)
        self.libc.syscall.restype = c.c_long
        self.libc.prctl.argtypes = [c.c_int, c.c_ulong, c.c_void_p, c.c_ulong, c.c_ulong]
        self.libc.prctl.restype = c.c_int
        self.libc.fstatfs.argtypes = [c.c_int, c.POINTER(StatFs)]
        self.libc.fstatfs.restype = c.c_int

    def scratch_filesystem(self, fd):
        result = StatFs()
        require(self.libc.fstatfs(fd, c.byref(result)) == 0 and result.type == 0x01021994)

    def abi(self):
        return int(self.libc.syscall(c.c_long(444), c.c_void_p(), c.c_size_t(0), c.c_uint(1)))

    def create(self):
        attributes = RulesetAttr(HANDLED_FS, HANDLED_NET)
        value = self.libc.syscall(c.c_long(444), c.byref(attributes), c.c_size_t(c.sizeof(attributes)), c.c_uint(0))
        require(value >= 0)
        return int(value)

    def create_abi3(self):
        attributes = RulesetAttrAbi3(ABI3_HANDLED_FS)
        value = self.libc.syscall(c.c_long(444), c.byref(attributes), c.c_size_t(c.sizeof(attributes)), c.c_uint(0))
        require(value >= 0)
        return int(value)

    def rule(self, ruleset, scratch_fd):
        rule = PathBeneath(SCRATCH_FS, scratch_fd)
        require(self.libc.syscall(c.c_long(445), c.c_int(ruleset), c.c_int(1), c.byref(rule), c.c_uint(0)) == 0)

    def no_new_privileges(self):
        require(self.libc.prctl(38, 1, None, 0, 0) == 0)
        require(self.libc.prctl(39, 0, None, 0, 0) == 1)

    def restrict(self, ruleset):
        require(self.libc.syscall(c.c_long(446), c.c_int(ruleset), c.c_uint(0)) == 0)

    def seccomp(self):
        values = filter_program()
        code = (SockFilter * len(values))(*(SockFilter(*row) for row in values))
        program = SockFprog(len(values), code)
        # TSYNC: a positive offending TID is failure, not success. This does not
        # replace the single-thread+external pids=1 prerequisite for Landlock.
        require(self.libc.syscall(c.c_long(317), c.c_uint(1), c.c_uint(1), c.byref(program)) == 0)


def install_confinement(scratch_fd):
    """Irreversibly restrict this candidate; success returns None, not readiness.

    On ANY exception the trusted entrypoint MUST terminate without reading input.
    No public test hooks, enable flags, caller receipts or fallback are accepted.
    """
    ruleset = None
    try:
        _supported()
        kernel = _Kernel()
        _process()
        _scratch(scratch_fd, kernel)
        _descriptors(scratch_fd)
        require(kernel.abi() >= 5)
        kernel.no_new_privileges()
        ruleset = kernel.create()
        require(ruleset not in (0, 1, 2, scratch_fd))
        kernel.rule(ruleset, scratch_fd)
        _process()
        kernel.restrict(ruleset)
        os.close(ruleset)
        ruleset = None
        _process()
        _descriptors(scratch_fd)
        kernel.seccomp()
        return None
    except Exception:
        raise ConfinementUnavailable() from None
    finally:
        if ruleset is not None:
            try:
                os.close(ruleset)
            except OSError:
                pass


def install_abi3_confinement(scratch_fd):
    """Explicit ABI3 composition; no ioctl/network LSM rights are represented.

    The SAME strict seccomp/FD/single-process policy compensates those missing
    LSM rights. This is selected only by the reviewed immutable Linux contract,
    never by retrying this entrypoint after an ABI5 failure. Before any stdin,
    both real kernel restrictions must succeed; failure requires termination.
    It issues no readiness receipt and accepts no enabling flag or callback.
    """
    ruleset = None
    try:
        _supported()
        kernel = _Kernel()
        _process()
        _scratch(scratch_fd, kernel)
        _descriptors(scratch_fd)
        require(kernel.abi() >= 3)
        kernel.no_new_privileges()
        ruleset = kernel.create_abi3()
        require(ruleset not in (0, 1, 2, scratch_fd))
        kernel.rule(ruleset, scratch_fd)
        _process()
        kernel.restrict(ruleset)
        os.close(ruleset)
        ruleset = None
        _process()
        _descriptors(scratch_fd)
        kernel.seccomp()
        return None
    except Exception:
        raise ConfinementUnavailable() from None
    finally:
        if ruleset is not None:
            try:
                os.close(ruleset)
            except OSError:
                pass
