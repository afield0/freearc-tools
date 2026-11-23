# SPDX-License-Identifier: GPL-2.0-only
"""Python FreeArc decoders. No subprocesses, native decoder bindings, or plugins.

LZMA and x86 BCJ follow Igor Pavlov's public-domain LZMA SDK algorithms.
FreeArc framing/REP/delta/4x4 follow the sources cited in README.extractor.md.
"""
from array import array
import re
import struct

from freearc_inspect import ParseError

CHUNK = 65536


class Unsupported(ParseError):
    pass


class Reader:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.buf = b''
        self.pos = 0

    def read(self, n):
        parts = []
        while n:
            if self.pos == len(self.buf):
                self.buf = next(self.chunks, b'')
                self.pos = 0
                if not self.buf:
                    break
            size = min(n, len(self.buf)-self.pos)
            parts.append(self.buf[self.pos:self.pos+size])
            self.pos += size
            n -= size
        return b''.join(parts)

    def exact(self, n):
        data = self.read(n)
        if len(data) != n:
            raise ParseError('truncated compressed stream')
        return data

    def byte(self):
        if self.pos == len(self.buf):
            self.buf = next(self.chunks, b'')
            self.pos = 0
            if not self.buf:
                raise ParseError('truncated range-coded stream')
        x = self.buf[self.pos]
        self.pos += 1
        return x

    def u32(self):
        return int.from_bytes(self.exact(4), 'little')

    def finish(self):
        if self.read(1):
            raise ParseError('trailing compressed bytes')


def memory(text):
    m = re.fullmatch(r'=?(\d+)(b|k|kb|m|mb|g|gb|\^)?', text)
    if not m:
        raise Unsupported('unsupported memory parameter: ' + repr(text))
    n = int(m[1])
    unit = m[2]
    if unit in (None, '^'):
        if n > 40:
            raise Unsupported('memory exponent too large')
        return 1 << n
    return n * {'b': 1, 'k': 1024, 'kb': 1024, 'm': 1024**2,
                'mb': 1024**2, 'g': 1024**3, 'gb': 1024**3}[unit]


def lzma_options(method, max_memory):
    opts = dict(dictionary=64*1024**2, lc=3, lp=0, pb=2)
    for param in method.split(':')[1:]:
        optional = param.startswith('*')
        p = param.lstrip('*')
        if re.fullmatch(r'(lc|lp|pb)=?\d+', p):
            opts[p[:2]] = int(p[2:].lstrip('='))
        elif p.startswith('d'):
            opts['dictionary'] = memory(p[1:])
        elif re.fullmatch(r'\d+(?:b|kb?|mb?|gb?|\^)', p):
            opts['dictionary'] = memory(p)
        elif (p in ('fastest', 'fast', 'normal', 'max', 'ultra', 'bt2', 'bt3', 'bt4', 'hc4', 'ht4')
              or re.fullmatch(r'(?:a|fb|mc)?\d+', p)
              or re.fullmatch(r'mf=?(?:bt2|bt3|bt4|hc4|ht4)', p)
              or re.fullmatch(r'h\d+(?:b|kb?|mb?|gb?)?', p)):
            pass  # Encoder-only settings; no effect on the bitstream decoder.
        elif not optional:
            raise Unsupported('unsupported LZMA parameter: ' + repr(p))
    if not (0 <= opts['lc'] <= 8 and 0 <= opts['lp'] <= 4 and 0 <= opts['pb'] <= 4):
        raise ParseError('invalid LZMA context properties')
    required = max(4096, opts['dictionary']) + (0x300 << (opts['lc']+opts['lp']))*2 + 65536
    if not opts['dictionary'] or required > max_memory:
        raise Unsupported('LZMA decoder exceeds memory limit')
    return opts


def probabilities(n):
    return array('H', [1024]) * n


class RangeDecoder:
    def __init__(self, reader):
        self.reader = reader
        if reader.byte() != 0:
            raise ParseError('invalid LZMA range header')
        self.code = int.from_bytes(reader.exact(4), 'big')
        self.range = 0xffffffff

    def normalize(self):
        if self.range < 1 << 24:
            self.range <<= 8
            self.code = ((self.code << 8) | self.reader.byte()) & 0xffffffff

    def bit(self, probs, index):
        p = probs[index]
        bound = (self.range >> 11) * p
        if self.code < bound:
            self.range = bound
            probs[index] = p + ((2048-p) >> 5)
            bit = 0
        else:
            self.range -= bound
            self.code -= bound
            probs[index] = p - (p >> 5)
            bit = 1
        self.normalize()
        return bit

    def tree(self, probs, bits, base=0, reverse=False):
        symbol, result = 1, 0
        for i in range(bits):
            b = self.bit(probs, base+symbol)
            symbol = (symbol << 1) | b
            result |= b << i
        return result if reverse else symbol - (1 << bits)

    def direct(self, bits):
        result = 0
        for _ in range(bits):
            self.range >>= 1
            b = int(self.code >= self.range)
            if b:
                self.code -= self.range
            result = (result << 1) | b
            self.normalize()
        return result


class LengthDecoder:
    def __init__(self):
        self.choice = probabilities(2)
        self.low, self.mid, self.high = probabilities(16*8), probabilities(16*8), probabilities(256)

    def decode(self, rc, pos):
        if not rc.bit(self.choice, 0):
            return rc.tree(self.low, 3, pos*8)
        if not rc.bit(self.choice, 1):
            return 8 + rc.tree(self.mid, 3, pos*8)
        return 16 + rc.tree(self.high, 8)


class Window:
    def __init__(self, size):
        self.data = bytearray(size)
        self.size, self.pos, self.total = size, 0, 0

    def previous(self, distance):
        if distance < 1 or distance > min(self.total, self.size):
            raise ParseError('invalid LZ match distance')
        return self.data[(self.pos-distance) % self.size]

    def put(self, value):
        self.data[self.pos] = value
        self.pos = (self.pos+1) % self.size
        self.total += 1


def decode_lzma(chunks, options):
    r = Reader(chunks)
    rc = RangeDecoder(r)
    window = Window(max(4096, options['dictionary']))
    is_match = probabilities(12*16)
    is_rep, g0, g1, g2 = [probabilities(12) for _ in range(4)]
    is_short = probabilities(12*16)
    slots, special, align = probabilities(4*64), probabilities(114), probabilities(16)
    literal = probabilities(0x300 << (options['lc']+options['lp']))
    lengths, rep_lengths = LengthDecoder(), LengthDecoder()
    state = rep0 = rep1 = rep2 = rep3 = previous = 0
    pos_mask, lit_mask = (1 << options['pb'])-1, (1 << options['lp'])-1
    out = bytearray()
    while True:
        pos = window.total & pos_mask
        if not rc.bit(is_match, state*16+pos):
            context = ((window.total & lit_mask) << options['lc']) + (previous >> (8-options['lc']))
            base, symbol = context*0x300, 1
            if state >= 7:
                match = window.previous(rep0+1)
                while symbol < 256:
                    match_bit = (match >> 7) & 1
                    match = (match << 1) & 255
                    bit = rc.bit(literal, base+((1+match_bit) << 8)+symbol)
                    symbol = (symbol << 1) | bit
                    if bit != match_bit:
                        break
            while symbol < 256:
                symbol = (symbol << 1) | rc.bit(literal, base+symbol)
            previous = symbol-256
            window.put(previous)
            out.append(previous)
            state = 0 if state < 4 else state-3 if state < 10 else state-6
        else:
            if rc.bit(is_rep, state):
                short = False
                if not rc.bit(g0, state):
                    if not rc.bit(is_short, state*16+pos):
                        short = True
                else:
                    if not rc.bit(g1, state):
                        distance = rep1
                    else:
                        if not rc.bit(g2, state):
                            distance = rep2
                        else:
                            distance = rep3
                            rep3 = rep2
                        rep2 = rep1
                    rep1, rep0 = rep0, distance
                if short:
                    length = 1
                    state = 9 if state < 7 else 11
                else:
                    length = rep_lengths.decode(rc, pos)+2
                    state = 8 if state < 7 else 11
            else:
                rep3, rep2, rep1 = rep2, rep1, rep0
                length = lengths.decode(rc, pos)+2
                state = 7 if state < 7 else 10
                slot = rc.tree(slots, 6, min(length-2, 3)*64)
                if slot < 4:
                    rep0 = slot
                else:
                    bits = (slot >> 1)-1
                    rep0 = (2 | (slot & 1)) << bits
                    if slot < 14:
                        rep0 += rc.tree(special, bits, rep0-slot-1, reverse=True)
                    else:
                        rep0 += (rc.direct(bits-4) << 4) + rc.tree(align, 4, reverse=True)
                        if rep0 == 0xffffffff:
                            break
            for _ in range(length):
                previous = window.previous(rep0+1)
                window.put(previous)
                out.append(previous)
        if len(out) >= CHUNK:
            yield bytes(out)
            out.clear()
    if rc.code != 0:
        raise ParseError('invalid LZMA end marker')
    r.finish()
    if out:
        yield bytes(out)


def decode_rep(chunks, max_memory):
    r = Reader(chunks)
    size = r.u32()
    if not 1 <= size <= max_memory//2:
        raise Unsupported('REP dictionary exceeds memory limit')
    window = Window(size)
    out = bytearray()
    while True:
        packed = r.u32()
        if packed == 0:
            break
        if packed > max_memory//2:
            raise Unsupported('REP block exceeds memory limit')
        data = r.exact(packed)
        if len(data) < 8:
            raise ParseError('short REP block')
        count = int.from_bytes(data[:4], 'little')
        header = 8+12*count
        if header > packed:
            raise ParseError('invalid REP table count')
        def word(at):
            return struct.unpack_from('<I', data, at)[0]
        cursor = header
        for i in range(count+1):
            length = word(4+8*count+4*i)
            if length > packed-cursor:
                raise ParseError('invalid REP literal length')
            for value in data[cursor:cursor+length]:
                window.put(value)
                out.append(value)
                if len(out) >= CHUNK:
                    yield bytes(out)
                    out.clear()
            cursor += length
            if i < count:
                length, distance = word(4+4*i), word(4+4*count+4*i)
                for _ in range(length):
                    value = window.previous(distance)
                    window.put(value)
                    out.append(value)
                    if len(out) >= CHUNK:
                        yield bytes(out)
                        out.clear()
        if cursor != packed:
            raise ParseError('unconsumed REP block bytes')
    r.finish()
    if out:
        yield bytes(out)


def decode_delta(chunks, max_memory):
    r = Reader(chunks)
    while True:
        first = r.read(4)
        if not first:
            return
        if len(first) != 4:
            raise ParseError('truncated delta header')
        size, table_size = int.from_bytes(first, 'little'), r.u32()
        if table_size % 4 or size*3 + table_size*3 > max_memory:
            raise Unsupported('delta block exceeds memory limit or invalid table length')
        skips, types, rows = [r.exact(table_size) for _ in range(3)]
        data, pos = bytearray(r.exact(size)), 0
        for j in range(0, table_size, 4):
            skip, typ, count = [struct.unpack_from('<I', x, j)[0] for x in (skips, types, rows)]
            width = typ.bit_length()-1
            if not 1 <= width <= 31:
                raise ParseError('invalid delta table type')
            pos += skip
            end = pos + width*count
            if end > size:
                raise ParseError('delta table outside block')
            immutable = [(typ >> k) & 1 for k in range(width)]
            imm_count = sum(immutable)
            if 0 < imm_count < width:
                old = data[pos:end]
                a, b = 0, imm_count*count
                for row in range(count):
                    for k in range(width):
                        if immutable[k]:
                            data[pos+row*width+k] = old[a]
                            a += 1
                        else:
                            data[pos+row*width+k] = old[b]
                            b += 1
            for row in range(1, count):
                carry = 0
                for k in range(width):
                    at = pos+row*width+k
                    if immutable[k]:
                        carry = 0
                    else:
                        value = data[at]+data[at-width]+carry
                        data[at], carry = value & 255, value >> 8
            pos = end
        for j in range(0, size, CHUNK):
            yield bytes(data[j:j+CHUNK])


def decode_exe(chunks):
    # Streaming port of LZMA SDK Bra86.c (Igor Pavlov, public domain).
    r, pending, ip, mask = Reader(chunks), b'', 0, 0
    allowed, bitnumber = (1, 1, 1, 0, 1, 0, 0, 0), (0, 1, 2, 2, 3, 3, 3, 3)
    while True:
        chunk = r.read(CHUNK)
        if not chunk:
            if pending:
                yield pending
            return
        data = bytearray(pending+chunk)
        pos, previous = 0, -1
        while pos < len(data)-4:
            if data[pos] & 254 != 232:
                pos += 1
                continue
            distance = pos-previous
            if distance > 3:
                mask = 0
            else:
                mask = (mask << (distance-1)) & 7
                if mask and (not allowed[mask] or data[pos+4-bitnumber[mask]] in (0, 255)):
                    previous, mask = pos, ((mask << 1) & 7) | 1
                    pos += 1
                    continue
            previous = pos
            if data[pos+4] in (0, 255):
                src = int.from_bytes(data[pos+1:pos+5], 'little')
                while True:
                    dest = (src-(ip+5+pos)) & 0xffffffff
                    if not mask:
                        break
                    index = bitnumber[mask]*8
                    if ((dest >> (24-index)) & 255) not in (0, 255):
                        break
                    src = dest ^ ((1 << (32-index))-1)
                data[pos+1:pos+4] = (dest & 0xffffff).to_bytes(3, 'little')
                data[pos+4] = 255 if (dest >> 24) & 1 else 0
                pos += 5
            else:
                mask = ((mask << 1) & 7) | 1
                pos += 1
        distance = pos-previous
        mask = 0 if distance > 3 else (mask << (distance-1)) & 7
        if pos:
            yield bytes(data[:pos])
        ip = (ip+pos) & 0xffffffff
        pending = bytes(data[pos:])


def inner_4x4(method):
    params = method.split(':')[1:]
    for i, p in enumerate(params):
        if not p or len(p) > 1024:
            raise ParseError('invalid 4x4 parameter')
        if not (p[0].isdigit() or (len(p) > 1 and p[1].isdigit())):
            return ':'.join(params[i:])
    return 'tor:3:1mb'


def decode_4x4(chunks, inner, limits, depth):
    r = Reader(chunks)
    if r.u32() != 0:
        raise Unsupported('unknown 4x4 stream version')
    while True:
        header = r.read(4)
        if not header:
            return
        if len(header) != 4:
            raise ParseError('truncated 4x4 block header')
        original, packed = int.from_bytes(header, 'little', signed=True), r.u32()
        if original < -1 or packed > limits['memory']//4 or original > limits['memory']//4:
            raise Unsupported('4x4 block exceeds memory limit or has invalid length')
        data = r.exact(packed)
        if original == -1:
            yield data
        else:
            count = 0
            for chunk in decode([data], inner, limits, depth+1):
                count += len(chunk)
                if count > original:
                    raise ParseError('4x4 output exceeds declared size')
                yield chunk
            if count != original:
                raise ParseError('4x4 output size mismatch')


def check_method(method, limits, depth=0):
    if depth > 8 or len(method) > 4096:
        raise Unsupported('codec nesting or method length limit exceeded')
    stages = method.split('+')
    if len(stages) > 16:
        raise Unsupported('too many codec stages')
    for stage in stages:
        name = stage.split(':')[0]
        if name == 'lzma':
            lzma_options(stage, limits['memory'])
        elif name == '4x4':
            check_method(inner_4x4(stage), limits, depth+1)
        elif name in ('rep', 'delta'):
            if any(not re.fullmatch(r'[A-Za-z0-9*=.-]+', p) for p in stage.split(':')[1:]):
                raise Unsupported('invalid codec parameter')
        elif stage not in ('storing', 'exe', 'srep_new', 'xtool:mzlib:mzstd'):
            raise Unsupported('unsupported compression method: ' + repr(stage))


def bounded(chunks, maximum):
    total = 0
    for chunk in chunks:
        total += len(chunk)
        if total > maximum:
            raise ParseError('decoded byte limit exceeded')
        if chunk:
            yield chunk


def decode(chunks, method, limits, depth=0):
    check_method(method, limits, depth)
    for stage in reversed(method.split('+')):
        name = stage.split(':')[0]
        if name == 'lzma':
            chunks = decode_lzma(chunks, lzma_options(stage, limits['memory']))
        elif name == 'rep':
            chunks = decode_rep(chunks, limits['memory'])
        elif name == 'delta':
            chunks = decode_delta(chunks, limits['memory'])
        elif stage == 'srep_new':
            from freearc_external import srep_v3
            chunks = srep_v3(Reader(chunks), limits)
        elif stage == 'xtool:mzlib:mzstd':
            from freearc_external import xtool
            chunks = xtool(Reader(chunks), limits['memory'])
        elif name == 'exe':
            chunks = decode_exe(chunks)
        elif name == '4x4':
            chunks = decode_4x4(chunks, inner_4x4(stage), limits, depth)
        chunks = bounded(chunks, limits['intermediate'])
    yield from chunks
