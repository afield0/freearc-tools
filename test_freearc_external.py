import struct
import unittest

from freearc_codecs import Reader, decode, Unsupported
from freearc_inspect import ParseError

LIMITS = dict(memory=64<<20, intermediate=64<<20)


def srep_block(literal, size, stats=b''):
    return struct.pack('<III', len(literal), size, len(stats))+bytes(16)+stats+literal


class ExternalStageTests(unittest.TestCase):
    magic = bytes.fromhex('17183526535245500301000000000000')
    xtl = b'XTL0'+struct.pack('<iB',1,9)+b'zlib+zstd'+struct.pack('<iiB',0,-2,0)

    def test_srep_saved_history_and_overlap(self):
        records = struct.pack('<IQI',0,4,2)+struct.pack('<IQI',2,4,2)
        first = srep_block(b'abcd',4,records)
        second = srep_block(b'',4)
        self.assertEqual(b''.join(decode([self.magic+first+second], 'srep_new', LIMITS)), b'abcdabcd')
        overlap = srep_block(b'a',5,struct.pack('<IQI',0,1,4))
        self.assertEqual(b''.join(decode([self.magic+overlap], 'srep_new', LIMITS)), b'aaaaa')

    def test_srep_checks_bounds_and_end(self):
        for block in (srep_block(b'a',2), srep_block(b'a',1,struct.pack('<IQI',0,3,1)),
                      srep_block(b'a',1)[:-1], bytes(8)+b'!'):
            with self.assertRaises(ParseError):
                list(decode([self.magic+block], 'srep_new', LIMITS))

    def test_xtool_literal_and_end(self):
        data = self.xtl+struct.pack('<iiqI',0,0,0,3)+b'abc'+struct.pack('<ii',0,-1)
        self.assertEqual(b''.join(decode([data], 'xtool:mzlib:mzstd', LIMITS)), b'abc')
        with self.assertRaises(ParseError):
            list(decode([data+b'?'], 'xtool:mzlib:mzstd', LIMITS))

    def test_xtool_requires_exact_recompression(self):
        record = struct.pack('<BiiiBI',0,8,16,-1,6,0)
        data = self.xtl+struct.pack('<iiq',0,1,16)+record
        with self.assertRaisesRegex(Unsupported,'codec=6'):
            list(decode([data],'xtool:mzlib:mzstd',LIMITS))
