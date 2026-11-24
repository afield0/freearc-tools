import contextlib
import hashlib
import io
import json
import lzma  # Independent native encoder oracle ONLY in tests, never used by extractor.
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zlib

import freearc_extract as ex
import freearc_codecs as codecs
import freearc_inspect as fmt
from test_freearc_inspect import integer, SAMPLE

ROOT = Path(__file__).parent
LIMITS = dict(memory=256*1024**2, intermediate=16*1024**2,
              output=16*1024**2, seconds=30)


def local(payload, typ, method='storing', original=None):
    plain = payload if original is None else original
    d = (fmt.MAGIC+integer(typ)+method.encode()+b'\0'+integer(len(plain))
         +integer(len(payload))+struct.pack('<I', zlib.crc32(plain)))
    return d+struct.pack('<I', zlib.crc32(d))


def make_archive(entries, method='storing', data_override=None):
    # entries = (full relative path, bytes, is_directory)
    plain = b''.join(e[1] for e in entries)
    data = plain if data_override is None else data_override
    prefix = SAMPLE[:31]+data
    base = len(prefix)
    dirs = ['']
    parents, names = [], []
    for path, _, _ in entries:
        parent, _, name = path.rpartition('/')
        if path.startswith('/') and not parent:
            parent = '/'
        if parent not in dirs:
            dirs.append(parent)
        parents.append(dirs.index(parent))
        names.append(name)
    directory = (integer(1)+integer(len(entries))+method.encode()+b'\0'
                 +integer(len(data))+integer(len(data))+integer(len(dirs)))
    directory += b''.join(d.encode()+b'\0' for d in dirs)
    directory += b''.join(n.encode()+b'\0' for n in names)
    directory += b''.join(integer(n) for n in parents)
    directory += b''.join(integer(len(e[1])) for e in entries)
    directory += b'\0\0\0\0'*len(entries)
    directory += bytes(e[2] for e in entries)
    directory += b''.join(struct.pack('<I', zlib.crc32(e[1])) for e in entries)
    directory += integer(0)
    content = prefix+directory+local(directory, 3)
    footbase = len(content)
    foot = integer(2)
    for typ, pos, payload in ((1, 0, SAMPLE[:8]), (3, base, directory)):
        foot += (integer(typ)+b'storing\0'+integer(footbase-pos)
                 +integer(len(payload))*2+struct.pack('<I', zlib.crc32(payload)))
    foot += b'\0'+integer(0)+b'\0'+integer(0)
    return content+foot+local(foot, 4)


class ExtractorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root/'input.arc'
        self.dest = self.root/'output'

    @contextlib.contextmanager
    def archive(self, data, **kwargs):
        self.path.write_bytes(data)
        with fmt.open_shared(self.path) as f:
            yield ex.Archive(f, self.path, LIMITS, **kwargs)

    def test_extract_and_independent_expected_contents(self):
        data = make_archive([('folder', b'', True), ('folder/empty', b'', False),
                             ('folder/a.txt', b'hello\n', False), ('b.bin', bytes(range(256)), False)])
        with self.archive(data) as a:
            result = a.process(self.dest)
        self.assertEqual(result['verified_files'], 3)
        self.assertEqual((self.dest/'folder/a.txt').read_bytes(), b'hello\n')
        self.assertEqual((self.dest/'b.bin').read_bytes(), bytes(range(256)))
        self.assertEqual(self.path.read_bytes(), data)

    def test_test_command_never_writes(self):
        with self.archive(make_archive([('a', b'abc', False)])) as a:
            self.assertTrue(a.process()['file_contents_verified'])
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_cli_default_destination(self):
        for filename, folder in [('game.v1.arc', 'game.v1'), ('plain', 'plain.extracted'),
                                 ('download.bin.filepart', 'download')]:
            with self.subTest(filename=filename):
                source = self.root / filename
                source.write_bytes(make_archive([('a', b'abc', False)]))
                args = ['extract', str(source), '--json']
                if filename.endswith('.filepart'):
                    args.append('--allow-filepart')
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(ex.main(args), 0)
                    self.assertEqual(ex.main(args), 2)
                self.assertEqual((self.root / folder / 'a').read_bytes(), b'abc')

    def test_paths_and_collisions_rejected(self):
        for path in ('../escape', '/absolute', 'C:/escape', '\\server\\share',
                     'a/../../escape', 'CON', 'aux.txt', 'COM¹', 'file:stream',
                     'trailing.', 'trailing ', 'a/./b', 'a\nb'):
            with self.subTest(path=path), self.assertRaises(fmt.ParseError):
                with self.archive(make_archive([(path, b'x', False)])):
                    pass
        for names in [('a', 'A'), ('a', 'a/b'), ('Dir/a', 'dir/b')]:
            with self.subTest(names=names), self.assertRaises(fmt.ParseError):
                with self.archive(make_archive([(n, b'x', False) for n in names])):
                    pass

    def test_existing_destination_is_preserved(self):
        self.dest.mkdir()
        sentinel = self.dest/'important'
        sentinel.write_text('keep')
        with self.archive(make_archive([('a', b'abc', False)])) as a:
            with self.assertRaises(fmt.ParseError):
                a.process(self.dest)
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_crc_failure_discards_all_output(self):
        data = bytearray(make_archive([('a', b'abc', False), ('b', b'def', False)]))
        data[34] ^= 1  # second file's stored data; metadata remains valid
        with self.archive(data) as a:
            with self.assertRaisesRegex(fmt.ParseError, 'CRC'):
                a.process(self.dest)
        self.assertFalse(self.dest.exists())
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_include_still_checks_unselected_files(self):
        data = make_archive([('a', b'abc', False), ('b', b'def', False)])
        with self.archive(data) as a:
            result = a.process(self.dest, ['a'])
        self.assertEqual(result['verified_files'], 2)
        self.assertEqual(result['extracted_files'], 1)
        self.assertEqual([p.name for p in self.dest.iterdir()], ['a'])

    def test_input_change_discards_output(self):
        with self.archive(make_archive([('a', b'abc', False)])) as a:
            original = a.unchanged
            def modify():
                with self.path.open('ab') as writer:
                    writer.write(b'x')
                original()
            with patch.object(a, 'unchanged', side_effect=modify):
                with self.assertRaisesRegex(fmt.ParseError, 'changed'):
                    a.process(self.dest)
        self.assertFalse(self.dest.exists())

    def test_partial_and_truncated_inputs_fail_without_output(self):
        data = make_archive([('a', b'abc', False)])
        for n in (0, 4, 8, 31, len(data)-1):
            with self.subTest(n=n), self.assertRaises(fmt.ParseError):
                with self.archive(data[:n]):
                    pass
        self.path = self.root/'input.filepart'
        with self.assertRaisesRegex(fmt.ParseError, 'partial download'):
            with self.archive(data):
                pass
        with self.archive(data, allow_filepart=True) as a:
            self.assertTrue(a.process()['partial_download_name'])

    def test_unsupported_and_output_limit_preflight(self):
        with self.archive(make_archive([('a', b'abc', False)], method='unknown')) as a:
            with self.assertRaises(codecs.Unsupported):
                a.process(self.dest)
        self.assertFalse(self.dest.exists())
        with self.archive(make_archive([('a', b'abc', False)])) as a:
            a.limits = dict(LIMITS, output=2)
            with self.assertRaisesRegex(fmt.ParseError, 'output exceeds'):
                a.process(self.dest)

    def test_surplus_decoded_bytes_rejected(self):
        with self.archive(make_archive([('a', b'abc', False)], data_override=b'abcd')) as a:
            with self.assertRaisesRegex(fmt.ParseError, 'trailing'):
                a.process(self.dest)
        self.assertFalse(self.dest.exists())

    def test_json_errors(self):
        self.path.write_bytes(SAMPLE)
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            code = ex.main(['test', str(self.path), '--json'])
        self.assertEqual(code, 2)
        self.assertIn('footer', json.loads(out.getvalue())['error'])

    def test_reparse_parent_rejected(self):
        original = Path.lstat
        def lstat(p):
            if p == self.root:
                return type('Stat', (), {'st_mode': 0o40700, 'st_file_attributes': 0x400})()
            return original(p)
        with patch.object(Path, 'lstat', lstat):
            with self.assertRaisesRegex(fmt.ParseError, 'reparse'):
                ex.check_destination_parent(self.root)


class CodecTests(unittest.TestCase):
    def test_python_lzma_against_independent_standard_library_encoder(self):
        rng = random.Random(33)
        for lc, lp, pb in ((3, 0, 2), (0, 2, 0), (4, 0, 4)):
            payload = rng.randbytes(4096)*7+b'abc'*10000
            encoded = lzma.compress(payload, format=lzma.FORMAT_RAW,
                filters=[dict(id=lzma.FILTER_LZMA1, dict_size=65536, lc=lc, lp=lp, pb=pb)])
            method = f'lzma:64kb:lc{lc}:lp{lp}:pb{pb}'
            for chunk_size in (1, 79, 65536):
                chunks = (encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size))
                self.assertEqual(b''.join(codecs.decode(chunks, method, LIMITS)), payload)

    def test_truncation_and_trailing_lzma(self):
        payload = b'abcd'*100
        encoded = lzma.compress(payload, format=lzma.FORMAT_RAW,
                               filters=[dict(id=lzma.FILTER_LZMA1, dict_size=65536)])
        for data in (encoded[:-1], encoded+b'x', b'\xff'+encoded[1:]):
            with self.assertRaises(fmt.ParseError):
                b''.join(codecs.decode([data], 'lzma:64kb', LIMITS))

    def test_limits_and_unsupported_methods(self):
        for method in ('lzma:999gb', 'lzma:lc99', 'tor:3', 'ppmd', 'aes', 'lzma:bogus', '4x4:tor:3'):
            with self.subTest(method=method), self.assertRaises(fmt.ParseError):
                codecs.check_method(method, LIMITS)
        with self.assertRaises(fmt.ParseError):
            list(codecs.decode([b'abcdef'], 'storing', dict(LIMITS, intermediate=2)))
        options = codecs.lzma_options('lzma:d=16:lc=3:lp=0:pb=2', LIMITS['memory'])
        self.assertEqual(options['dictionary'], 65536)
        self.assertEqual(codecs.memory('16^'), 65536)

    def test_rep_overlapping_match_and_bounds(self):
        # One literal 'a', followed by a 20-byte back-reference of distance one.
        block = struct.pack('<IIIII', 1, 20, 1, 1, 0)+b'a'
        encoded = struct.pack('<II', 64, len(block))+block+struct.pack('<I', 0)
        self.assertEqual(b''.join(codecs.decode([encoded], 'rep', LIMITS)), b'a'*21)
        bad = bytearray(encoded)
        struct.pack_into('<I', bad, 16, 100)
        with self.assertRaises(fmt.ParseError):
            b''.join(codecs.decode([bad], 'rep', LIMITS))

    def test_4x4_stored_blocks_and_bad_size(self):
        encoded = struct.pack('<IiI', 0, -1, 3)+b'abc'
        self.assertEqual(b''.join(codecs.decode([encoded], '4x4:storing', LIMITS)), b'abc')
        bad = struct.pack('<IiI', 0, 2, 3)+b'abc'
        with self.assertRaises(fmt.ParseError):
            b''.join(codecs.decode([bad], '4x4:storing', LIMITS))

    def test_delta_table_reconstruction(self):
        # Two 2-byte rows, both columns differenced. 0x01ff + 0x0002 = 0x0201.
        data = struct.pack('<IIIII', 4, 4, 0, 4, 2)+bytes.fromhex('ff010200')
        self.assertEqual(b''.join(codecs.decode([data], 'delta', LIMITS)), bytes.fromhex('ff010102'))

    def test_malformed_framing(self):
        rng = random.Random(31)
        for method in ('rep', 'delta', '4x4:storing'):
            for _ in range(50):
                data = rng.randbytes(rng.randrange(64))
                try:
                    list(codecs.decode([data], method, dict(LIMITS, intermediate=1024)))
                except fmt.ParseError:
                    pass


class GenuineFixtureTests(unittest.TestCase):
    def test_pinned_genuine_archives_extract_and_verify(self):
        manifest = json.loads((ROOT/'freearc_fixtures/manifest.json').read_text())
        counts = {'genuine_m0': (11, 29786), 'genuine_lzma_64kb': (1, 262144),
                  'genuine_lzma_lc0lp2pb0': (1, 524288), 'genuine_4x4_lzma': (1, 1048576),
                  'genuine_rep_lzma': (1, 970752), 'genuine_exe_lzma': (1, 262144),
                  'genuine_delta_lzma': (1, 524288)}
        for name, (count, size) in counts.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                path = ROOT/'freearc_fixtures'/(name+'.arc')
                bundled = {'genuine_exe_lzma', 'genuine_delta_lzma', 'genuine_lzma_lc0lp2pb0'}
                if name not in bundled and not path.exists():
                    external = os.environ.get('FREEARC_TEST_FIXTURES')
                    if not external:
                        self.skipTest('optional upstream fixture; see README.md')
                    path = Path(external) / path.name
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), manifest['files'][path.name]['sha256'])
                with fmt.open_shared(path) as f:
                    a = ex.Archive(f, path, LIMITS)
                    report = a.process(Path(td)/'out')
                    entries = a.entries
                self.assertEqual(report['verified_files'], count)
                self.assertEqual(report['verified_bytes'], size)
                for e in entries:
                    target = Path(td)/'out'/Path(*e['output_parts'])
                    if e['is_directory']:
                        self.assertTrue(target.is_dir())
                    else:
                        content = target.read_bytes()
                        self.assertEqual(len(content), e['original_size'])
                        self.assertEqual(zlib.crc32(content), e['crc32'])
                if name == 'genuine_m0':
                    # Independent literal from upstream fixture generator, not our parser.
                    self.assertEqual((Path(td)/'out/misc/hello.txt').read_bytes(), b'Hello from FreeArc 0.67\r\n')


if __name__ == '__main__':
    unittest.main()
