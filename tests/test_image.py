import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from firmware_image_check.core import address_range, compare, parse, policy
from firmware_image_check.cli import main, render


def ihex(address, data=b'', code=0):
    raw = bytes([len(data)]) + address.to_bytes(2, 'big') + bytes([code]) + data
    return ':' + (raw + bytes([-sum(raw) & 255])).hex().upper()


def srec(code, address, data=b''):
    width = {0:2,1:2,2:3,3:4,5:2,6:3,7:4,8:3,9:2}[code]
    raw = bytes([width + len(data) + 1]) + address.to_bytes(width, 'big') + data
    return 'S%d' % code + (raw + bytes([~sum(raw) & 255])).hex().upper()


def image(*records):
    return parse('\n'.join(records + (ihex(0, code=1),)))


class ImageTests(unittest.TestCase):
    def test_known_checksum_vector(self):
        value = image(':10010000214601360121470136007EFE09D2190140')
        self.assertEqual(value.segments[0].start, 0x100)
        self.assertEqual(value.segments[0].data.hex(), '214601360121470136007efe09d21901')

    def test_checksum_rejected(self):
        with self.assertRaisesRegex(ValueError, 'checksum'):
            image(':0100000000FE')

    def test_count_rejected(self):
        with self.assertRaisesRegex(ValueError, 'count'):
            image(':0200000000FE')

    def test_missing_eof(self):
        with self.assertRaisesRegex(ValueError, 'termination'):
            parse(ihex(0, b'ab'))

    def test_data_after_eof(self):
        with self.assertRaisesRegex(ValueError, 'after termination'):
            parse(ihex(0, code=1) + '\n' + ihex(0, b'ab'))

    def test_linear_address(self):
        value = image(ihex(0, b'\x08\x00', 4), ihex(2, b'abc'), ihex(0, b'\x08\x00\x00\x02', 5))
        self.assertEqual(value.entry, 0x8000002)
        self.assertEqual(value.segments[0].start, 0x8000002)

    def test_segment_address(self):
        value = image(ihex(0, b'\x12\x34', 2), ihex(2, b'a'), ihex(0, b'\x12\x34\x00\x02', 3))
        self.assertEqual(value.entry, 0x12342)
        self.assertEqual(value.segments[0].start, 0x12342)

    def test_control_shape(self):
        with self.assertRaisesRegex(ValueError, 'control'):
            image(ihex(1, b'\x00\x01', 4), ihex(0, b'a'))

    def test_window_overflow(self):
        with self.assertRaisesRegex(ValueError, 'window'):
            image(ihex(65535, b'ab'))

    def test_conflicting_entry(self):
        with self.assertRaisesRegex(ValueError, 'entrypoints'):
            image(ihex(0, b'a'), ihex(0, b'\x00\x00\x00\x01', 5), ihex(0, b'\x00\x00\x00\x02', 5))

    def test_overlap_even_identical(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            image(ihex(1, b'ab'), ihex(2, b'b'))

    def test_hash_independent_of_order_and_partition(self):
        a = image(ihex(0, b'abc'))
        b = image(ihex(1, b'bc'), ihex(0, b'a'))
        self.assertEqual(a.summary()['addressed_sha256'], b.summary()['addressed_sha256'])
        self.assertEqual(compare(a, b)['changed_blocks'], [])

    def test_hash_address_sensitive(self):
        self.assertNotEqual(image(ihex(0, b'a')).summary()['addressed_sha256'], image(ihex(1, b'a')).summary()['addressed_sha256'])

    def test_srec_widths_and_count(self):
        for code, end in ((1,9),(2,8),(3,7)):
            with self.subTest(code=code):
                value = parse('\n'.join([srec(0, 0, b'test'), srec(code, 32, b'abc'), srec(5, 1), srec(end, 32)]))
                self.assertEqual(value.entry, 32)
                self.assertEqual(value.size, 3)

    def test_srec_count_bad(self):
        with self.assertRaisesRegex(ValueError, 'count'):
            parse('\n'.join([srec(1, 0, b'a'), srec(5, 2), srec(9, 0)]))

    def test_srec_termination_bad(self):
        with self.assertRaisesRegex(ValueError, 'termination'):
            parse('\n'.join([srec(1, 0, b'a'), srec(7, 0)]))

    def test_srec_checksum_bad(self):
        with self.assertRaisesRegex(ValueError, 'checksum'):
            parse('S10400006199\n' + srec(9, 0))

    def test_srec_mixed_widths(self):
        with self.assertRaisesRegex(ValueError, 'mixed'):
            parse('\n'.join([srec(1, 0, b'a'), srec(2, 1, b'b'), srec(8, 0)]))

    def test_size_budget(self):
        with self.assertRaisesRegex(ValueError, 'limit'):
            parse(ihex(0, b'ab') + '\n' + ihex(0, code=1), max_bytes=1)

    def test_ranges_and_policies(self):
        value = image(ihex(0, b'abcd'))
        self.assertEqual(address_range('0x0:4'), (0,4))
        self.assertEqual(address_range('010:020'), (10, 20))
        self.assertEqual(address_range('0X10:0x20'), (16, 32))
        self.assertEqual(policy(value, [(0,2),(2,4)]), [])
        self.assertEqual(len(policy(value, [(0,3)], [(3,4)], 3, True)), 4)

    def test_invalid_range(self):
        for text in ('0:0', '2:1', '0:0x100000001', 'word', '-1:2', '0o10:20', '0x:20'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                address_range(text)

    def test_erased_byte_not_hole(self):
        before = image(ihex(0, b'\xff'), ihex(2, b'\x00'))
        after = image(ihex(1, b'\xff'), ihex(2, b'\x01'))
        change = compare(before, after, 4)['changed_blocks'][0]
        self.assertEqual((change['added_bytes'], change['removed_bytes'], change['modified_bytes']), (1,1,1))

    def test_cross_block_change(self):
        before = image(ihex(3, b'ab'))
        after = image(ihex(3, b'cd'))
        self.assertEqual(len(compare(before, after, 4)['changed_blocks']), 2)

    def test_sparse_32_bit_space(self):
        before = image(ihex(0, b'a'), ihex(0, b'\xff\xff', 4), ihex(65535, b'z'))
        after = image(ihex(0, b'b'), ihex(0, b'\xff\xff', 4), ihex(65535, b'z'))
        self.assertEqual(len(compare(before, after, 1048576)['changed_blocks']), 1)

    def test_block_size_rejected(self):
        value = image(ihex(0, b'a'))
        for size in (0, 3, -1, 2**21, True):
            with self.subTest(size=size), self.assertRaises(ValueError):
                compare(value, value, size)

    def test_demo_and_cli_status(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'report.json'
            self.assertEqual(main(['demo', '--format', 'json', '--output', str(output)]), 0)
            self.assertTrue(json.loads(output.read_text())['changed_blocks'])
            self.assertEqual(main(['demo', '--output', str(output), '--fail-on-change']), 1)
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(['check', str(Path(folder) / 'missing.hex')]), 2)
            self.assertNotIn('Traceback', errors.getvalue())

    def test_html_escapes(self):
        report = {'image': {'bytes': 1}, 'violations': ['<script>alert(1)</script>']}
        self.assertNotIn('<script>', render(report, 'html'))

    def test_cli_does_not_overwrite_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.hex'
            text = ihex(0, b'ab') + '\n' + ihex(0, code=1)
            path.write_text(text)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['check', str(path), '--output', str(path)]), 2)
            self.assertEqual(path.read_text(), text)


if __name__ == '__main__':
    unittest.main()
