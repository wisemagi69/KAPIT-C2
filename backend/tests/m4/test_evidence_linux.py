"""Pure Linux-candidate tests: NEVER install host filters or invoke a syscall."""
from contextlib import ExitStack
import ctypes as c
import errno
import os
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from apps.operations import evidence_linux as linux


STATUS = """Name:\tpython3
Uid:\t65532\t65532\t65532\t65532
Gid:\t65532\t65532\t65532\t65532
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
Threads:\t1
NoNewPrivs:\t1
"""
MOUNTS = """1 0 0:1 / / ro - overlay overlay ro
2 1 0:2 / /scratch rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=65536k,nr_inodes=128
"""


def evaluate(program, number, arch=linux.AUDIT_ARCH_X86_64, arguments=(0, 0, 0, 0, 0, 0)):
    """Independent tiny interpreter for the actual classic-BPF tuples."""
    pc, accumulator = 0, 0
    for _ in range(4096):
        code, jt, jf, value = program[pc]
        if code == 0x20:
            if value == 0: accumulator = number & 0xffffffff
            elif value == 4: accumulator = arch
            else:
                index, half = divmod(value - 16, 8)
                accumulator = (arguments[index] >> (32 if half else 0)) & 0xffffffff
        elif code == 0x15:
            pc += jt if accumulator == value else jf
        elif code == 0x45:
            pc += jt if accumulator & value else jf
        elif code == 0x06:
            return value
        else:
            raise AssertionError("Unknown BPF opcode")
        pc += 1
    raise AssertionError("Filter did not terminate")


class LinuxConfinementPureTests(unittest.TestCase):
    def rejected(self, call):
        with self.assertRaises(linux.ConfinementUnavailable) as failure:
            call()
        self.assertTrue(str(failure.exception) == "LINUX_CONFINEMENT_UNAVAILABLE", "Fixed denial required")

    def test_structures_match_linux_amd64_uapi_without_loading_libc(self):
        self.assertEqual(c.sizeof(linux.RulesetAttr), 16)
        self.assertEqual(c.sizeof(linux.PathBeneath), 12)
        self.assertEqual(linux.PathBeneath.parent_fd.offset, 8)
        self.assertEqual(c.sizeof(linux.SockFilter), 8)
        self.assertEqual(linux.SockFprog.filter.offset, 8)
        self.assertEqual(c.sizeof(linux.SockFprog), 16)
        self.assertEqual(c.sizeof(linux.StatFs), 120)

    def test_landlock_handles_all_write_execute_device_rights_but_grants_only_scratch_regular_files(self):
        self.assertEqual(linux.HANDLED_FS, sum(1 << n for n in (0, 1, *range(4, 16))))
        self.assertEqual(linux.SCRATCH_FS & ~linux.HANDLED_FS, 0)
        for right in (linux.FS_EXECUTE, linux.FS_MAKE_CHAR, linux.FS_MAKE_BLOCK, linux.FS_MAKE_SOCK,
                      linux.FS_MAKE_FIFO, linux.FS_MAKE_SYM, linux.FS_IOCTL_DEV):
            self.assertEqual(linux.SCRATCH_FS & right, 0)
        self.assertEqual(linux.HANDLED_NET, 3)

    def test_actual_filter_allows_only_named_minimal_syscalls(self):
        code = linux.filter_program()
        self.assertTrue(len(code) < 4096)
        for number in linux.SYSCALLS.values():
            self.assertEqual(evaluate(code, number), linux.ALLOW)
        for number in range(550):
            if number not in linux.SYSCALLS.values():
                self.assertEqual(evaluate(code, number), linux.DENY)
        self.assertEqual(evaluate(code, 999999), linux.DENY)

    def test_architecture_x32_and_negative_syscalls_cannot_bypass_filter(self):
        code = linux.filter_program()
        for number in (0, 1, 59, 257):
            self.assertEqual(evaluate(code, number, 0x40000003), linux.KILL_PROCESS)
            self.assertEqual(evaluate(code, number | linux.X32_SYSCALL_BIT), linux.KILL_PROCESS)
        self.assertEqual(evaluate(code, -1), linux.KILL_PROCESS)

    def test_prlimit64_requires_self_readback_and_both_null_pointer_halves(self):
        code = linux.filter_program()
        self.assertEqual(evaluate(code, 302, arguments=(0, 0, 0, 1234, 0, 0)), linux.ALLOW)
        for args in ((1, 0, 0, 1234, 0, 0), (1 << 32, 0, 0, 1234, 0, 0),
                     (0, 0, 1, 1234, 0, 0), (0, 0, 1 << 32, 1234, 0, 0),
                     (0, 0, 0xffffffffffffffff, 1234, 0, 0)):
            self.assertEqual(evaluate(code, 302, arguments=args), linux.DENY)

    def test_exec_threads_network_ioctl_mount_ipc_proc_handles_and_kernel_interfaces_denied(self):
        denied = {"ioctl": 16, "socket": 41, "connect": 42, "socketpair": 53, "clone": 56, "fork": 57,
                  "vfork": 58, "execve": 59, "kill": 62, "shmget": 29, "semget": 64, "msgget": 68,
                  "ptrace": 101, "mount": 165, "umount2": 166, "prctl": 157, "unshare": 272,
                  "setns": 308, "name_to_handle_at": 303, "open_by_handle_at": 304, "process_vm_readv": 310,
                  "process_vm_writev": 311, "seccomp": 317, "memfd_create": 319, "userfaultfd": 323,
                  "execveat": 322, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
                  "clone3": 435, "pidfd_getfd": 438, "landlock_create": 444, "landlock_add": 445,
                  "landlock_restrict": 446, "memfd_secret": 447, "mq_open": 240}
        for number in denied.values():
            self.assertEqual(evaluate(linux.filter_program(), number), linux.DENY)

    def test_windows_or_wrong_arch_refuses_before_libc_or_any_fd_action(self):
        with patch.object(linux.sys, "platform", "win32"), patch.object(linux, "_Kernel") as kernel:
            self.rejected(lambda: linux.install_confinement(5))
            kernel.assert_not_called()
        with patch.object(linux.sys, "platform", "linux"), patch.object(linux.platform, "machine", return_value="aarch64"):
            self.rejected(linux._supported)

    def setup_installer(self, stack, events, *, abi=5):
        kernel = SimpleNamespace()
        for name in ("no_new_privileges", "rule", "restrict", "seccomp"):
            setattr(kernel, name, Mock(side_effect=lambda *args, name=name: events.append(name)))
        kernel.abi = Mock(side_effect=lambda: events.append("abi") or abi)
        kernel.create = Mock(side_effect=lambda: events.append("create") or 9)
        stack.enter_context(patch.object(linux, "_supported"))
        stack.enter_context(patch.object(linux, "_Kernel", return_value=kernel))
        for name in ("_process", "_scratch", "_descriptors"):
            stack.enter_context(patch.object(linux, name, side_effect=lambda *args, name=name: events.append(name)))
        stack.enter_context(patch.object(linux.os, "close", side_effect=lambda fd: events.append("close:" + str(fd))))
        return kernel

    def test_install_requires_actual_all_stage_success_and_returns_no_receipt(self):
        events = []
        with ExitStack() as stack:
            self.setup_installer(stack, events)
            self.assertIsNone(linux.install_confinement(5))
        self.assertTrue(events == ["_process", "_scratch", "_descriptors", "abi", "no_new_privileges",
            "create", "rule", "_process", "restrict", "close:9", "_process", "_descriptors", "seccomp"])

    def test_missing_or_old_abi_refuses_before_ruleset_or_filter(self):
        for abi in (-1, 0, 1, 4):
            events = []
            with ExitStack() as stack:
                kernel = self.setup_installer(stack, events, abi=abi)
                self.rejected(lambda: linux.install_confinement(5))
                kernel.create.assert_not_called()
                kernel.seccomp.assert_not_called()

    def test_each_installation_failure_is_fixed_and_closes_only_its_created_ruleset(self):
        for stage in ("no_new_privileges", "create", "rule", "restrict", "seccomp"):
            events = []
            with ExitStack() as stack:
                kernel = self.setup_installer(stack, events)
                getattr(kernel, stage).side_effect = RuntimeError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
                self.rejected(lambda: linux.install_confinement(5))
                if stage in ("rule", "restrict", "seccomp"):
                    self.assertTrue(events.count("close:9") == 1)
                else:
                    self.assertTrue(not any(x.startswith("close:") for x in events))

    def test_proc_identity_requires_no_caps_no_new_privs_single_thread_and_fixed_uid(self):
        linux._status(STATUS)
        for changed in (STATUS.replace("Threads:\t1", "Threads:\t2"), STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                        STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
                        STATUS.replace("65532", "0"), STATUS + "Threads:\t1\n"):
            self.rejected(lambda: linux._status(changed))

    def test_mount_policy_requires_readonly_root_exact_tmpfs_mount_and_flags(self):
        linux._mounts(MOUNTS, "0:2")
        for changed in (MOUNTS.replace(" / ro ", " / rw "), MOUNTS.replace("- tmpfs", "- ext4"),
                        MOUNTS.replace("noexec", "exec"), MOUNTS.replace("0:2", "0:3"),
                        MOUNTS + MOUNTS.splitlines()[1] + "\n", MOUNTS.replace(" - ", " ? ")):
            self.rejected(lambda: linux._mounts(changed, "0:2"))

    def test_syscall_wrappers_use_exact_abi_rules_and_tsync_positive_return_is_failure(self):
        kernel = linux._Kernel.__new__(linux._Kernel)
        kernel.libc = SimpleNamespace(syscall=Mock(return_value=9), prctl=Mock())
        self.assertEqual(kernel.create(), 9)
        args = kernel.libc.syscall.call_args.args
        self.assertEqual(args[0].value, 444)
        self.assertEqual(args[1]._obj.handled_access_fs, linux.HANDLED_FS)
        self.assertEqual(args[1]._obj.handled_access_net, linux.HANDLED_NET)
        kernel.libc.syscall.return_value = 0
        kernel.rule(9, 5)
        args = kernel.libc.syscall.call_args.args
        self.assertEqual(args[0].value, 445)
        self.assertEqual(args[3]._obj.parent_fd, 5)
        self.assertEqual(args[3]._obj.allowed_access, linux.SCRATCH_FS)
        kernel.seccomp()
        args = kernel.libc.syscall.call_args.args
        self.assertEqual((args[0].value, args[1].value, args[2].value), (317, 1, 1))
        self.assertEqual(args[3]._obj.len, len(linux.filter_program()))
        kernel.libc.syscall.return_value = 999
        self.rejected(kernel.seccomp)

    def test_existing_write_device_socket_or_unexpected_fd_refuses(self):
        fake = SimpleNamespace(F_GETFL=3, fcntl=Mock(return_value=os.O_RDONLY))
        entries = {0: stat.S_IFIFO, 1: stat.S_IFIFO, 2: stat.S_IFIFO, 5: stat.S_IFDIR}
        def flags(fd, _): return {0: os.O_RDONLY, 1: os.O_WRONLY, 2: os.O_WRONLY, 5: linux.O_PATH}[fd]
        fake.fcntl.side_effect = flags
        with patch.dict(sys.modules, {"fcntl": fake}), patch.object(linux.os, "listdir", return_value=["0", "1", "2", "5"]), \
             patch.object(linux.os, "fstat", side_effect=lambda fd: SimpleNamespace(st_mode=entries[fd])), \
             patch.object(linux.os, "readlink", return_value="pipe:[7]") as readlink:
            linux._descriptors(5)
            for mode in (stat.S_IFREG, stat.S_IFCHR, stat.S_IFSOCK):
                entries[1] = mode
                self.rejected(lambda: linux._descriptors(5))
            entries[1] = stat.S_IFIFO
            readlink.return_value = "/scratch/named-fifo"
            self.rejected(lambda: linux._descriptors(5))
        with patch.dict(sys.modules, {"fcntl": fake}), patch.object(linux.os, "listdir", return_value=["8"]), \
             patch.object(linux.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)):
            fake.fcntl.side_effect = None; fake.fcntl.return_value = os.O_WRONLY
            self.rejected(lambda: linux._descriptors(5))

    def test_scratch_quota_identity_owner_flags_and_close_are_actual_preflight_requirements(self):
        fake = SimpleNamespace(F_GETFL=3, fcntl=Mock(return_value=linux.O_PATH | linux.O_DIRECTORY | linux.O_NOFOLLOW))
        item = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=65532, st_gid=65532, st_dev=2, st_ino=7)
        volume = SimpleNamespace(f_frsize=4096, f_blocks=16384, f_files=128)
        kernel = SimpleNamespace(scratch_filesystem=Mock())
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"fcntl": fake}))
            stack.enter_context(patch.object(linux.os, "O_CLOEXEC", 0x80000, create=True))
            stack.enter_context(patch.object(linux.os, "fstat", return_value=item))
            stack.enter_context(patch.object(linux.os, "fstatvfs", return_value=volume, create=True))
            stack.enter_context(patch.object(linux.os, "major", return_value=0, create=True))
            stack.enter_context(patch.object(linux.os, "minor", return_value=2, create=True))
            stack.enter_context(patch.object(linux.os, "open", return_value=8))
            close = stack.enter_context(patch.object(linux.os, "close"))
            stack.enter_context(patch.object(linux, "_read", return_value=MOUNTS))
            linux._scratch(5, kernel)
            close.assert_called_with(8)
            for change in ("bytes", "inodes", "owner", "flags", "fs"):
                volume.f_blocks, volume.f_files, item.st_uid = 16384, 128, 65532
                fake.fcntl.return_value = linux.O_PATH | linux.O_DIRECTORY | linux.O_NOFOLLOW
                kernel.scratch_filesystem.side_effect = None
                if change == "bytes": volume.f_blocks += 1
                if change == "inodes": volume.f_files += 1
                if change == "owner": item.st_uid = 0
                if change == "flags": fake.fcntl.return_value = os.O_WRONLY
                if change == "fs": kernel.scratch_filesystem.side_effect = linux.ConfinementUnavailable()
                self.rejected(lambda: linux._scratch(5, kernel))
