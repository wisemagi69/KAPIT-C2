"""Finite synthetic metadata archives; no extraction or Docker/filesystem links."""
import io
import tarfile
import unittest

from infra import evidence_software_links as links


ORIGINAL = '/lib/x86_64-linux-gnu/libbz2.so.1.0'


def archive(target='libbz2.so.1.0.4', *, name='libbz2.so.1.0', kind=tarfile.SYMTYPE):
    sink = io.BytesIO()
    with tarfile.open(fileobj=sink, mode='w', format=tarfile.USTAR_FORMAT) as output:
        info = tarfile.TarInfo(name); info.type = kind; info.linkname = target
        output.addfile(info)
    return sink.getvalue()[:1536]


def altered(raw, start, value):
    header = bytearray(raw[:512]); header[start:start+len(value)] = value
    header[148:156] = b'        '
    header[148:156] = f'{sum(header):06o}'.encode()+b'\x00 '
    return bytes(header)+raw[512:]


class SoftwareLinkTests(unittest.TestCase):
    def test_relative_absolute_and_fixed_software_directories(self):
        self.assertEqual(links.resolve_link_metadata(archive(), ORIGINAL), '/lib/x86_64-linux-gnu/libbz2.so.1.0.4')
        for parent in sorted(links.SOFTWARE_DIRS):
            source = parent+'/libbz2.so.1.0'
            self.assertEqual(links.resolve_link_metadata(archive('./libbz2.so.1.0.4'), source), parent+'/libbz2.so.1.0.4')
            target = parent+'/libbz2.so.1.0.4'
            self.assertEqual(links.resolve_link_metadata(archive(target), ORIGINAL), target)
        self.assertEqual(links.resolve_link_metadata(archive('../x86_64-linux-gnu/libbz2.so.1.0.4'), ORIGINAL), '/lib/x86_64-linux-gnu/libbz2.so.1.0.4')
        self.assertEqual(links.resolve_link_metadata(archive('../../usr/lib/x86_64-linux-gnu/libbz2.so.1.0.4'), ORIGINAL), '/usr/lib/x86_64-linux-gnu/libbz2.so.1.0.4')

    def test_original_must_be_exact_safe_software_child(self):
        for path in ['', 'lib/x', '//lib64/x', '/etc/x', '/lib64/../lib64/x', '/usr/local/lib/tree/x', '/lib64/', '/lib64/..', '/lib64/a:b', '/lib64/a\\b', '/lib64/a\x00b', '/lib64/a b', '/lib64/é', 1, '/lib64/'+'x'*513]:
            with self.subTest(path=repr(path)), self.assertRaises(links.SoftwareLinkUnavailable):
                links.resolve_link_metadata(archive(), path)

    def test_target_escape_opaque_intermediate_or_nonportable_path_refused(self):
        for target in ['/etc/passwd', '/proc/self/mem', '/lib64/tree/lib.so', '/lib64/../lib64/lib.so',
                       'foo/../lib.so', '../etc/passwd', '../../../../usr/local/lib/x', '//lib64/x',
                       'C:/lib/x', '\\host\\share', 'lib\\x', '', '.', '..', 'lib.so/', 'a//b',
                       'lib.so\n', 'lib.so\x00suffix', 'é.so']:
            raw = altered(archive(), 157, b'\x00'*100)
            raw = altered(raw, 157, target.encode('utf-8'))
            with self.subTest(target=repr(target)), self.assertRaises(links.SoftwareLinkUnavailable):
                links.resolve_link_metadata(raw, ORIGINAL)

    def test_original_basename_header_binding(self):
        for name in ['other.so', 'dir/libbz2.so.1.0', '../libbz2.so.1.0', '/libbz2.so.1.0', '']:
            with self.subTest(name=name), self.assertRaises(links.SoftwareLinkUnavailable):
                links.resolve_link_metadata(archive(name=name), ORIGINAL)

    def test_single_symlink_only_no_regular_hardlink_directory_device_or_extensions(self):
        for kind in [tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                     tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE]:
            with self.subTest(kind=kind), self.assertRaises(links.SoftwareLinkUnavailable):
                links.resolve_link_metadata(archive(kind=kind), ORIGINAL)

    def test_size_payload_second_member_and_trailing_archive_refused(self):
        valid = archive()
        for raw in [altered(valid, 124, b'00000000001\x00'), valid[:512]+archive(),
                    valid+b'\x00'*512+archive(), valid[:1024]+b'X'+valid[1025:]]:
            with self.assertRaises(links.SoftwareLinkUnavailable): links.resolve_link_metadata(raw, ORIGINAL)

    def test_checksum_magic_version_prefix_padding_and_numeric_tamper(self):
        valid = archive()
        damaged = bytearray(valid); damaged[20] ^= 1
        bad = [bytes(damaged), altered(valid, 257, b'ustar  \x00'), altered(valid, 263, b'01'),
               altered(valid, 345, b'prefix'), altered(valid, 500, b'x'),
               altered(valid, 100, b'\x80'), altered(valid, 124, b'-1'), altered(valid, 136, b'8'),
               altered(valid, 30, b'\x00hidden'), altered(valid, 200, b'\x00hidden')]
        for raw in bad:
            with self.assertRaises(links.SoftwareLinkUnavailable): links.resolve_link_metadata(raw, ORIGINAL)

    def test_bounds_types_end_blocks_and_zero_padding(self):
        valid = archive()
        for raw in [None, bytearray(valid), b'', valid[:512], valid[:1024], valid[:-1], valid+b'\x00', valid+b'\x00'*65536]:
            with self.assertRaises(links.SoftwareLinkUnavailable): links.resolve_link_metadata(raw, ORIGINAL)
        self.assertEqual(links.resolve_link_metadata(valid+b'\x00'*4096, ORIGINAL), '/lib/x86_64-linux-gnu/libbz2.so.1.0.4')

    def test_failure_has_only_fixed_message(self):
        with self.assertRaises(links.SoftwareLinkUnavailable) as context:
            links.resolve_link_metadata(b'private-looking input', '/etc/private')
        self.assertEqual(str(context.exception), 'SOFTWARE_LINK_METADATA_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
