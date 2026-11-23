"""Synthetic FreeArc structure tests.

Stored directory fixtures follow the referenced source; they are NOT evidence of
successful enumeration of a separately produced real FreeArc archive.
"""
import io
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import freearc_inspect as arc

def integer(n):
    for width in range(1, 9):
        if n < 1 << (7 * width):
            return ((n << width) | ((1 << (width - 1)) - 1)).to_bytes(width, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def desc(payload, typ, method=b'storing'):
    body = arc.MAGIC + integer(typ) + method + b'\0' + integer(len(payload)) * 2
    body += struct.pack('<I', zlib.crc32(payload))
    return body + struct.pack('<I', zlib.crc32(body))


TEST_HEADER = arc.MAGIC + bytes((1, 2, 3, 4))
SAMPLE = TEST_HEADER + desc(TEST_HEADER, 1) + b'X'


def fixture():
    header = SAMPLE[:31]
    data = b'abc'
    base = len(header) + len(data)
    directory = (integer(1) + integer(1) + b'storing\0' + integer(3) + integer(3)
                 + integer(1) + b'folder\0' + b'hello.txt\0' + integer(0)
                 + integer(3) + struct.pack('<I', 123) + b'\0'
                 + struct.pack('<I', zlib.crc32(data)) + integer(0))
    content = header + data + directory + desc(directory, 3)
    footbase = len(content)
    foot = integer(2)
    for typ, pos, payload in [(1, 0, SAMPLE[:8]), (3, base, directory)]:
        foot += integer(typ) + b'storing\0' + integer(footbase-pos)
        foot += integer(len(payload))*2 + struct.pack('<I', zlib.crc32(payload))
    foot += b'\0' + integer(0) + b'\0' + integer(0)
    return content + foot + desc(foot, 4), directory, base


class ParserTests(unittest.TestCase):
    def inspect_bytes(self, data, suffix='.arc', **kwargs):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ('archive' + suffix)
            path.write_bytes(data)
            before = path.read_bytes()
            r = arc.inspect(path, **kwargs)
            self.assertEqual(before, path.read_bytes())
            return r

    def test_synthetic_header_sample(self):
        r = self.inspect_bytes(SAMPLE, '.filepart')
        self.assertTrue(r['header_validated'])
        self.assertEqual(r['structures'][0]['descriptor_end'], 31)
        self.assertEqual(r['structures'][0]['version_bytes'], '01 02 03 04')
        self.assertFalse(r['archive_complete'])
        self.assertEqual(r['files'], [])

    def test_every_truncation_of_synthetic_header(self):
        for n in range(31):
            with self.subTest(n=n):
                r = self.inspect_bytes(SAMPLE[:n])
                self.assertFalse(r.get('header_validated', False))

    def test_integers_all_widths(self):
        for n in [0, 127, 128, 16383, 16384, 2**64-1] + [2**(7*i) for i in range(1, 9)]:
            encoded = integer(n)
            self.assertEqual(arc.Cursor(encoded).uint(), n)
            for cut in range(len(encoded)):
                with self.assertRaises(arc.ParseError):
                    arc.Cursor(encoded[:cut]).uint()

    def test_stored_directory_and_footer(self):
        data, _, _ = fixture()
        r = self.inspect_bytes(data)
        self.assertTrue(r['enumeration_complete'])
        self.assertFalse(r['archive_complete'])
        self.assertEqual(r['files'][0]['path'], 'folder/hello.txt')
        self.assertEqual(r['files'][0]['original_size'], 3)
        self.assertIsNone(r['files'][0]['compressed_size'])
        self.assertEqual(r['solid_blocks'][0]['compressed_size'], 3)

    def test_filepart_never_complete_even_with_footer(self):
        r = self.inspect_bytes(fixture()[0], '.filepart')
        self.assertFalse(r['enumeration_complete'])
        self.assertFalse(r['archive_complete'])

    def test_missing_footer_but_local_directory_available(self):
        data, directory, base = fixture()
        r = self.inspect_bytes(data[:base + len(directory) + len(desc(directory, 3))])
        self.assertEqual(len(r['files']), 1)
        self.assertFalse(r['enumeration_complete'])

    def test_bad_crc_and_invalid_length(self):
        bad = bytearray(SAMPLE)
        bad[30] ^= 1
        self.assertFalse(self.inspect_bytes(bad).get('header_validated', False))
        with self.assertRaises(arc.ParseError):
            arc.directory(integer(2**64-1), 0)
        with self.assertRaises(arc.ParseError):
            arc.descriptor(desc(b'x' * 100, 1), 8)
        with self.assertRaises(arc.ParseError):
            arc.Cursor(b'x' * 65537).string()

    def test_payload_crc_failure(self):
        bad = bytearray(SAMPLE)
        bad[7] ^= 1
        r = self.inspect_bytes(bad)
        self.assertIn('CRC mismatch', r['structures'][0]['payload_status'])

    def test_unsupported_metadata_codec(self):
        r = self.inspect_bytes(b'x' * 8 + desc(b'x' * 8, 3, b'lzma'))
        self.assertTrue(any('unsupported metadata codec' in x for x in r['limitations']))

    def test_short_reads_and_growth(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'growing.filepart'
            path.write_bytes(SAMPLE)
            with arc.open_shared(path) as f:
                s = arc.Snapshot(f)
                with open(path, 'ab') as writer:
                    writer.write(b'more')
                self.assertEqual(s.read(0, 1000), SAMPLE)
                with open(path, 'r+b') as writer:
                    writer.truncate(4)
                self.assertEqual(s.read(0, 1000), arc.MAGIC)

    def test_large_offset_without_large_file(self):
        class FakeFile(io.BytesIO):
            def fileno(self):
                return 0
        stat = type('Stat', (), {'st_size': 101*1024**3, 'st_mtime_ns': 0})()
        with patch.object(arc.os, 'fstat', return_value=stat):
            s = arc.Snapshot(FakeFile())
            self.assertEqual(s.read(100*1024**3, 4096), b'')

    def test_random_malformed_inputs_are_bounded(self):
        rng = random.Random(7)
        for _ in range(200):
            data = rng.randbytes(rng.randrange(150))
            for parser, args in [(arc.descriptor, (data, 1000)),
                                 (arc.directory, (data, 1000)), (arc.footer, (data, 1000))]:
                try:
                    parser(*args)
                except arc.ParseError:
                    pass

    def test_cli_json_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'sample.filepart'
            p.write_bytes(SAMPLE)
            with patch('sys.stdout', new_callable=io.StringIO) as out:
                self.assertEqual(arc.main(['list', str(p), '--json']), 4)
                self.assertEqual(json.loads(out.getvalue())['exit_code'], 4)
            p.write_bytes(b'no archive')
            with patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(arc.main(['info', str(p), '--json']), 3)


if __name__ == '__main__':
    unittest.main()
