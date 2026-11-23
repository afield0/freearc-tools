import random
import struct
import unittest
import zlib

from freearc_codecs import decode
from freearc_deflate import compress
from freearc_inspect import ParseError


def reference(data, level, memory, window):
    encoder = zlib.compressobj(level, zlib.DEFLATED, -window, memory)
    return encoder.compress(data) + encoder.flush()


class DeflateTests(unittest.TestCase):
    def test_encoder_bytes(self):
        random_bytes = random.Random(42).randbytes(8000)
        for level in (1, 3, 4, 6, 9):
            for data in (b'', b'abcde' * 1500, random_bytes, random_bytes * 9):
                with self.subTest(level=level, length=len(data)):
                    self.assertEqual(compress(data, level, 8, 15), reference(data, level, 8, 15))

    def test_xtool_interleaved_records(self):
        inputs = [b'Pattern A' * 400, bytes(range(256)) * 8]
        outputs = [reference(data, 9, 8, 15) for data in inputs]
        header = b'XTL0'+struct.pack('<iB',1,9)+b'zlib+zstd'+struct.pack('<iiB',0,-2,0)
        table = struct.pack('<iiq', 0, len(inputs), sum(map(len, inputs)))
        for data, coded in zip(inputs, outputs):
            table += struct.pack('<BiiiBI', 0, len(coded), len(data), -201, 7, 0x1f10)
        gaps = [b'before', b'between', b'after']
        wire = header+table+b''.join(inputs)+b''.join(struct.pack('<I',len(g))+g for g in gaps)+struct.pack('<ii',0,-2147483648)
        def run(w):
            return b''.join(decode([w], 'xtool:mzlib:mzstd', dict(memory=64<<20, intermediate=64<<20)))
        self.assertEqual(run(wire), gaps[0]+outputs[0]+gaps[1]+outputs[1]+gaps[2])
        corrupted = bytearray(wire)
        struct.pack_into('<i', corrupted, len(header)+17, len(outputs[0])+1)
        with self.assertRaises(ParseError):
            run(corrupted)
