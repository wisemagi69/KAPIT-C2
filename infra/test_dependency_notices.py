"""Synthetic archive guards and read-only checks of original locked artifacts."""
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import struct
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from infra import dependency_notices as notices


def wheel(members):
    target = io.BytesIO()
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return target.getvalue()


def npm(members):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode='w') as archive:
        for name, data, kind in members:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            if kind == 'symlink':
                member.type, member.linkname, member.size = tarfile.SYMTYPE, '../secret', 0
            if kind == 'hardlink':
                member.type, member.linkname, member.size = tarfile.LNKTYPE, '../secret', 0
            archive.addfile(member, io.BytesIO(data) if kind == 'file' else None)
    return gzip.compress(target.getvalue(), mtime=0)


def lock():
    return {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/demo': {
        'version': '1.0', 'resolved': 'https://registry.npmjs.org/demo/-/demo-1.0.tgz',
        'integrity': 'sha512-' + base64.b64encode(b'x' * 64).decode(), 'license': 'MIT'}}}


class NoticeTests(unittest.TestCase):
    def test_wheel_identity_attribution_and_exact_license_bytes(self):
        text = b'Copyright Synthetic Author\r\nPermission granted.\r\n'
        raw = wheel([('demo-1.0.dist-info/METADATA', b'Name: demo\nVersion: 1.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n'),
                     ('demo-1.0.dist-info/licenses/LICENSE', text), ('demo/source.py', b'PRIVATE_CANARY_NOT_A_NOTICE')])
        entry = notices.describe(raw, 'wheel', 'demo', '1.0', 'fixture.whl')
        self.assertEqual(entry['declared_license'], ['MIT'])
        self.assertEqual(entry['notices'][0]['sha256'], hashlib.sha256(text).hexdigest())
        self.assertEqual(entry['notices'][0]['text'].encode(), text)
        self.assertEqual(entry['artifact_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(entry['gaps'], [])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(entry))

    def test_web_metadata_identity_and_bundled_notices_preserved(self):
        raw = npm([('package/package.json', b'{"name":"demo","version":"1.0","license":"MIT"}', 'file'),
                   ('package/LICENSE', b'Copyright demo\n', 'file'),
                   ('package/vendor/COPYING.BSD', b'Copyright bundled vendor\n', 'file')])
        entry = notices.describe(raw, 'npm', 'demo', '1.0', 'cache', 'MIT')
        self.assertEqual(len(entry['notices']), 2)
        self.assertEqual(entry['legal_review'], 'NOT_PERFORMED')
        with self.assertRaisesRegex(notices.NoticeError, 'IDENTITY_MISMATCH'):
            notices.describe(raw, 'npm', 'wrong', '1.0', 'cache')

    def test_missing_and_unknown_license_are_explicit(self):
        raw = wheel([('demo-1.0.dist-info/METADATA', b'Name: demo\nVersion: 1.0\nLicense-File: special.txt\n')])
        row = notices.describe(raw, 'wheel', 'demo', '1.0', 'cache')
        self.assertEqual(row['gaps'], ['DECLARED_LICENSE_FILE_NOT_CAPTURED', 'DECLARED_LICENSE_UNKNOWN', 'NOTICE_TEXT_NOT_FOUND'])

    def test_unsupported_notice_encoding_not_claimed_preserved_as_text(self):
        raw = wheel([('demo-1.0.dist-info/METADATA', b'Name: demo\nVersion: 1.0\n'), ('LICENSE', b'\xff\x00')])
        row = notices.describe(raw, 'wheel', 'demo', '1.0', 'cache')
        self.assertIn('NOTICE_ENCODING_UNSUPPORTED', row['gaps'])
        self.assertIsNone(row['notices'][0]['text'])
        self.assertEqual(row['notices'][0]['sha256'], hashlib.sha256(b'\xff\x00').hexdigest())

    def test_traversal_absolute_windows_and_ambiguous_paths_denied(self):
        for name in ('../LICENSE', '/LICENSE', 'C:/LICENSE', 'x\\LICENSE', 'a/../LICENSE', 'a//LICENSE', 'NUL.txt', 'a./LICENSE', 'a/\x00LICENSE'):
            with self.subTest(name=name), self.assertRaises(notices.NoticeError):
                notices.safe_name(name)
            # ZipInfo construction itself normalizes Windows separators and NUL;
            # those two guards above exercise the original unsafe string directly.
            if '\\' not in name and '\x00' not in name:
                with self.assertRaises(notices.NoticeError):
                    notices.archive_members(wheel([(name, b'x')]), 'wheel')

    def test_duplicate_casefold_members_denied(self):
        with self.assertRaisesRegex(notices.NoticeError, 'DUPLICATE'):
            notices.archive_members(wheel([('LICENSE', b'one'), ('license', b'two')]), 'wheel')

    def test_forged_low_eocd_count_rejected_before_zipfile_allocation(self):
        raw = bytearray(wheel([('LICENSE', b'one'), ('NOTICE', b'two'), ('COPYING', b'three')]))
        end = raw.rfind(b'PK\x05\x06')
        struct.pack_into('<HH', raw, end + 8, 1, 1)
        for limit in (2, notices.MAX_MEMBERS):
            with self.subTest(limit=limit), patch.object(notices, 'MAX_MEMBERS', limit), patch.object(notices.zipfile, 'ZipFile') as constructor:
                with self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_LIMIT'):
                    notices.archive_members(bytes(raw), 'wheel')
                constructor.assert_not_called()

    def test_central_record_span_mismatch_rejected_before_zipfile(self):
        original = wheel([('LICENSE', b'one')])
        central = original.find(b'PK\x01\x02')
        for field_offset, value in ((28, 65535), (30, 65535), (32, 65535)):
            raw = bytearray(original)
            struct.pack_into('<H', raw, central + field_offset, value)
            with self.subTest(field=field_offset), patch.object(notices.zipfile, 'ZipFile') as constructor:
                with self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_LIMIT'):
                    notices.archive_members(bytes(raw), 'wheel')
                constructor.assert_not_called()

    def test_central_signature_and_count_mismatch_rejected_before_zipfile(self):
        original = wheel([('LICENSE', b'one')])
        bad_signature = bytearray(original)
        bad_signature[original.find(b'PK\x01\x02')] = 0
        high_count = bytearray(original)
        struct.pack_into('<HH', high_count, original.rfind(b'PK\x05\x06') + 8, 2, 2)
        for raw in (bad_signature, high_count):
            with patch.object(notices.zipfile, 'ZipFile') as constructor:
                with self.assertRaises(notices.NoticeError):
                    notices.archive_members(bytes(raw), 'wheel')
                constructor.assert_not_called()

    def test_tar_symlink_and_hardlink_denied_without_extraction(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind), self.assertRaisesRegex(notices.NoticeError, 'TYPE_REFUSED'):
                notices.archive_members(npm([('package/LICENSE', b'', kind)]), 'npm')

    def test_zip_symlink_denied(self):
        for name in ('LICENSE', 'LICENSE/'):
            target = io.BytesIO()
            with zipfile.ZipFile(target, 'w') as archive:
                item = zipfile.ZipInfo(name)
                item.create_system, item.external_attr = 3, 0o120777 << 16
                archive.writestr(item, '../secret')
            with self.subTest(name=name), self.assertRaisesRegex(notices.NoticeError, 'TYPE_REFUSED'):
                notices.archive_members(target.getvalue(), 'wheel')

    def test_archive_member_expansion_text_and_count_limits(self):
        raw = wheel([('LICENSE', b'a' * 100)])
        with patch.object(notices, 'MAX_MEMBER', 50), self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_LIMIT'):
            notices.archive_members(raw, 'wheel')
        with patch.object(notices, 'MAX_TEXT', 50), self.assertRaisesRegex(notices.NoticeError, 'NOTICE_LIMIT'):
            notices.archive_members(raw, 'wheel')
        with patch.object(notices, 'MAX_MEMBERS', 1), self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_LIMIT'):
            notices.archive_members(wheel([('LICENSE', b'x'), ('NOTICE', b'y')]), 'wheel')
        with patch.object(notices, 'MAX_EXPANDED', 100), self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_LIMIT'):
            notices.archive_members(npm([('package/LICENSE', b'a' * 1000, 'file')]), 'npm')
        with patch.object(notices, 'MAX_ARCHIVE', 1), self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_LIMIT'):
            notices.archive_members(raw, 'wheel')
        with patch.object(notices, 'MAX_NOTICES', 1), self.assertRaisesRegex(notices.NoticeError, 'NOTICE_LIMIT'):
            notices.archive_members(raw, 'wheel')

    def test_corrupt_archives_fail_closed(self):
        for kind in ('wheel', 'npm'):
            with self.subTest(kind=kind), self.assertRaisesRegex(notices.NoticeError, 'ARCHIVE_REFUSED'):
                notices.archive_members(b'not an archive', kind)

    def test_guarded_read_rejects_hash_size_and_hardlink(self):
        with tempfile.TemporaryDirectory(dir=notices.ROOT) as directory:
            root = Path(directory)
            original, alias = root / 'artifact', root / 'alias'
            original.write_bytes(b'altered')
            with self.assertRaisesRegex(notices.replay.ReplayError, 'HASH_MISMATCH'):
                notices.replay.read_fixed(original, 32, hashlib.sha256(b'expected').hexdigest())
            with self.assertRaisesRegex(notices.replay.ReplayError, 'INPUT_REFUSED'):
                notices.replay.read_fixed(original, 1)
            os.link(original, alias)
            with self.assertRaisesRegex(notices.replay.ReplayError, 'INPUT_REFUSED'):
                notices.replay.read_fixed(original, 32)

    def test_metadata_duplicate_and_identity_denied(self):
        for metadata in (b'Name: demo\nName: other\nVersion: 1.0\n', b'Name: demo\nVersion: 2.0\n'):
            with self.assertRaisesRegex(notices.NoticeError, 'IDENTITY_MISMATCH'):
                notices.describe(wheel([('demo.dist-info/METADATA', metadata)]), 'wheel', 'demo', '1.0', 'cache')
        with self.assertRaisesRegex(notices.NoticeError, 'DUPLICATE_JSON_KEY'):
            notices.load_json(b'{"name":"one","name":"two"}')

    def test_web_lock_refuses_unknown_origins_links_nested_and_weak_integrity(self):
        for field, value in [('resolved', 'https://other.invalid/archive'), ('link', True), ('integrity', 'sha1-Zm9v'), ('integrity', True)]:
            item = lock()
            item['packages']['node_modules/demo'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(notices.NoticeError):
                notices.web_inputs(json.dumps(item).encode())
        item = lock()
        item['packages']['node_modules/demo/node_modules/hidden'] = item['packages'].pop('node_modules/demo')
        with self.assertRaises(notices.NoticeError):
            notices.web_inputs(json.dumps(item).encode())

    def test_markdown_fences_preserve_notice_without_embedded_close(self):
        text = 'copyright\n```\n<script>not executable</script>\n'
        row = notices.describe(wheel([('demo.dist-info/METADATA', b'Name: demo\nVersion: 1.0\n'), ('LICENSE', text.encode())]), 'wheel', 'demo', '1.0', 'cache')
        rendered = notices.render_notices({'packages': [row]}).decode()
        self.assertIn('````text\n' + text + '````', rendered)
        self.assertEqual(notices.render_notices({'packages': [row]}), notices.render_notices({'packages': [row]}))

    def test_prepare_is_read_only_and_failure_does_not_write_or_echo(self):
        with patch.object(notices, 'build_inventory', return_value={'packages': []}), patch.object(notices, 'write_outputs') as write, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(notices.main([]), 2)
            write.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['status'], 'PREPARED_NOT_WRITTEN')
        with patch.object(notices, 'build_inventory', side_effect=OSError('PRIVATE_SECRET_CANARY')), patch.object(notices, 'write_outputs') as write, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(notices.main(['--write']), 2)
            write.assert_not_called()
        self.assertNotIn('PRIVATE_SECRET_CANARY', output.getvalue())

    def test_fixed_output_hardlink_refused_before_either_write(self):
        with tempfile.TemporaryDirectory(dir=notices.ROOT) as directory:
            root = Path(directory)
            protected, output, other = root / 'protected', root / 'out.json', root / 'out.md'
            protected.write_bytes(b'UNCHANGED')
            os.link(protected, output)
            with patch.object(notices, 'OUTPUT_JSON', output), patch.object(notices, 'OUTPUT_TEXT', other), self.assertRaises(notices.replay.ReplayError):
                notices.write_outputs({'packages': []})
            self.assertEqual(protected.read_bytes(), b'UNCHANGED')
            self.assertFalse(other.exists())

    def test_fixed_output_determinism_and_only_two_files(self):
        with tempfile.TemporaryDirectory(dir=notices.ROOT) as directory:
            root = Path(directory)
            output, other = root / 'out.json', root / 'out.md'
            with patch.object(notices, 'OUTPUT_JSON', output), patch.object(notices, 'OUTPUT_TEXT', other):
                notices.write_outputs({'packages': [], 'license_complete': False})
                first = output.read_bytes(), other.read_bytes()
                notices.write_outputs({'packages': [], 'license_complete': False})
                self.assertEqual(first, (output.read_bytes(), other.read_bytes()))
            self.assertEqual({p.name for p in root.iterdir()}, {'out.json', 'out.md'})

    def test_actual_original_artifact_closure_and_determinism(self):
        inventory = notices.build_inventory()
        self.assertEqual(len(inventory['packages']), 39)
        self.assertEqual(sum(r['ecosystem'] == 'python' for r in inventory['packages']), 12)
        self.assertEqual(sum(r['ecosystem'] == 'web' for r in inventory['packages']), 27)
        self.assertFalse(inventory['license_complete'])
        self.assertEqual(notices.json_bytes(inventory), notices.json_bytes(notices.build_inventory()))
        self.assertTrue(all(row['artifact_sha256'] and row['metadata_sha256'] for row in inventory['packages']))

    def test_altered_web_archive_refuses_before_notice_output(self):
        real = notices.replay.read_fixed
        def altered(path, limit, expected_hash=None):
            raw = real(path, limit, expected_hash)
            if str(path).startswith(str(notices.CACHE)):
                return raw + b'TAMPER'
            return raw
        with patch.object(notices.replay, 'read_fixed', side_effect=altered), self.assertRaisesRegex(notices.NoticeError, 'WEB_INTEGRITY_MISMATCH'):
            notices.build_inventory()

    def test_pinned_web_lock_change_refused(self):
        with patch.object(notices, 'WEB_LOCK_SHA256', '0' * 64), self.assertRaisesRegex(notices.replay.ReplayError, 'HASH_MISMATCH'):
            notices.build_inventory()


if __name__ == '__main__':
    unittest.main()
