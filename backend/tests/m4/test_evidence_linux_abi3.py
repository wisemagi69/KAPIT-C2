"""Pure explicit ABI3 composition tests; no Linux syscall/native installation."""
from contextlib import ExitStack
import ctypes as c
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from apps.operations import evidence_linux as linux
from tests.m4.test_evidence_linux import evaluate, STATUS, MOUNTS


class Abi3ConfinementPureTests(unittest.TestCase):
    def rejected(self, call):
        with self.assertRaises(linux.ConfinementUnavailable) as failure:
            call()
        self.assertTrue(str(failure.exception) == "LINUX_CONFINEMENT_UNAVAILABLE", "Fixed denial required")

    def setup_kernel(self, stack, events, abi=3):
        kernel = SimpleNamespace()
        for name in ("no_new_privileges", "rule", "restrict", "seccomp"):
            setattr(kernel, name, Mock(side_effect=lambda *args, name=name: events.append(name)))
        kernel.abi = Mock(side_effect=lambda: events.append("abi") or abi)
        kernel.create_abi3 = Mock(side_effect=lambda: events.append("create_abi3") or 9)
        kernel.create = Mock(side_effect=lambda: events.append("create_abi5") or 9)
        stack.enter_context(patch.object(linux, "_supported"))
        stack.enter_context(patch.object(linux, "_Kernel", return_value=kernel))
        for name in ("_process", "_scratch", "_descriptors"):
            stack.enter_context(patch.object(linux, name, side_effect=lambda *args, name=name: events.append(name)))
        stack.enter_context(patch.object(linux.os, "close", side_effect=lambda fd: events.append("close:" + str(fd))))
        return kernel

    def test_explicit_policy_uses_eight_byte_fs_only_attr_with_truncate_not_network_or_ioctl(self):
        self.assertEqual(linux.ABI3_POLICY_ID, "linux-amd64-landlock3-seccomp-v1")
        self.assertEqual(c.sizeof(linux.RulesetAttrAbi3), 8)
        self.assertEqual(tuple(linux.RulesetAttrAbi3._fields_), (("handled_access_fs", c.c_uint64),))
        self.assertEqual(linux.ABI3_HANDLED_FS, sum(1 << bit for bit in (0, 1, *range(4, 15))))
        self.assertEqual(linux.ABI3_HANDLED_FS & linux.FS_TRUNCATE, linux.FS_TRUNCATE)
        self.assertEqual(linux.ABI3_HANDLED_FS & linux.FS_IOCTL_DEV, 0)
        self.assertEqual(linux.SCRATCH_FS & ~linux.ABI3_HANDLED_FS, 0)
        self.assertEqual(c.sizeof(linux.RulesetAttr), 16)  # ABI5 schema retained.
        self.assertEqual(linux.HANDLED_FS & linux.FS_IOCTL_DEV, linux.FS_IOCTL_DEV)

    def test_abi3_success_installs_both_controls_and_closes_ruleset_before_filter(self):
        events = []
        with ExitStack() as stack:
            kernel = self.setup_kernel(stack, events)
            self.assertIsNone(linux.install_abi3_confinement(5))
            kernel.create.assert_not_called()
            kernel.rule.assert_called_once_with(9, 5)
        self.assertTrue(events == ["_process", "_scratch", "_descriptors", "abi", "no_new_privileges",
            "create_abi3", "rule", "_process", "restrict", "close:9", "_process", "_descriptors", "seccomp"])

    def test_missing_abi1_abi2_fail_before_rule_or_filter_and_no_automatic_abi5_retry(self):
        for abi in (-1, 0, 1, 2):
            with ExitStack() as stack:
                kernel = self.setup_kernel(stack, [], abi)
                self.rejected(lambda: linux.install_abi3_confinement(5))
                kernel.create_abi3.assert_not_called()
                kernel.create.assert_not_called()
                kernel.seccomp.assert_not_called()

    def test_historical_abi5_entrypoint_still_rejects_abi3_and_calls_only_abi5_creator(self):
        for abi in (3, 4):
            with ExitStack() as stack:
                kernel = self.setup_kernel(stack, [], abi)
                self.rejected(lambda: linux.install_confinement(5))
                kernel.create.assert_not_called()
                kernel.create_abi3.assert_not_called()
        with ExitStack() as stack:
            kernel = self.setup_kernel(stack, [], 5)
            self.assertIsNone(linux.install_confinement(5))
            kernel.create.assert_called_once_with()
            kernel.create_abi3.assert_not_called()

    def test_abi3_has_no_fallback_on_restrict_or_filter_or_native_error(self):
        for stage in ("no_new_privileges", "create_abi3", "rule", "restrict", "seccomp"):
            events = []
            with ExitStack() as stack:
                kernel = self.setup_kernel(stack, events)
                getattr(kernel, stage).side_effect = OSError("SYNTHETIC_INTERNAL_DETAIL")
                self.rejected(lambda: linux.install_abi3_confinement(5))
                kernel.create.assert_not_called()
                self.assertEqual(events.count("close:9"), int(stage in ("rule", "restrict", "seccomp")))

    def test_bad_process_scratch_or_descriptor_audit_never_reaches_landlock_or_seccomp(self):
        for stage in ("_process", "_scratch", "_descriptors"):
            with ExitStack() as stack:
                kernel = self.setup_kernel(stack, [])
                stack.enter_context(patch.object(linux, stage, side_effect=linux.ConfinementUnavailable()))
                self.rejected(lambda: linux.install_abi3_confinement(5))
                kernel.create_abi3.assert_not_called()
                kernel.seccomp.assert_not_called()

    def test_final_thread_or_fd_audit_after_landlock_failure_still_never_returns_success(self):
        for name, answers in (("_process", (None, None, linux.ConfinementUnavailable())),
                              ("_descriptors", (None, linux.ConfinementUnavailable()))):
            with ExitStack() as stack:
                kernel = self.setup_kernel(stack, [])
                stack.enter_context(patch.object(linux, name, side_effect=answers))
                self.rejected(lambda: linux.install_abi3_confinement(5))
                kernel.seccomp.assert_not_called()

    def test_exact_syscall_wrapper_supplies_only_eight_bytes_and_no_unsupported_rights(self):
        kernel = linux._Kernel.__new__(linux._Kernel)
        kernel.libc = SimpleNamespace(syscall=Mock(return_value=9))
        self.assertEqual(kernel.create_abi3(), 9)
        args = kernel.libc.syscall.call_args.args
        self.assertEqual((args[0].value, args[2].value, args[3].value), (444, 8, 0))
        self.assertIs(type(args[1]._obj), linux.RulesetAttrAbi3)
        self.assertEqual(args[1]._obj.handled_access_fs, linux.ABI3_HANDLED_FS)
        kernel.libc.syscall.return_value = -1
        self.rejected(kernel.create_abi3)

    def test_missing_lsm_network_ioctl_rights_have_absolute_post_filter_denials(self):
        code = linux.filter_program()
        for number in (16, *range(41, 59), 59, 62, 101, 157, 165, 166, 240, 272, 303, 304,
                       308, 310, 311, 317, 319, 322, 323, 425, 426, 427, 435, 438, 444, 445, 446, 447):
            self.assertEqual(evaluate(code, number), linux.DENY)
        for number in (0, 1, 257):
            self.assertEqual(evaluate(code, number | linux.X32_SYSCALL_BIT), linux.KILL_PROCESS)
            self.assertEqual(evaluate(code, number, 0x40000003), linux.KILL_PROCESS)

    def test_resource_readback_remains_self_only_null_new_limit_for_both_pointer_halves(self):
        code = linux.filter_program()
        self.assertEqual(evaluate(code, 302), linux.ALLOW)
        for args in ((1, 0, 0, 0, 0, 0), (1 << 32, 0, 0, 0, 0, 0),
                     (0, 0, 1, 0, 0, 0), (0, 0, 1 << 32, 0, 0, 0)):
            self.assertEqual(evaluate(code, 302, arguments=args), linux.DENY)

    def test_shared_proc_mount_and_platform_checks_are_not_disabled_for_abi3(self):
        linux._status(STATUS)
        linux._mounts(MOUNTS, "0:2")
        self.rejected(lambda: linux._status(STATUS.replace("Threads:\t1", "Threads:\t2")))
        self.rejected(lambda: linux._mounts(MOUNTS.replace("noexec", "exec"), "0:2"))
        with patch.object(linux.sys, "platform", "win32"), patch.object(linux, "_Kernel") as kernel:
            self.rejected(lambda: linux.install_abi3_confinement(5))
            kernel.assert_not_called()
