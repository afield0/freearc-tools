# SPDX-License-Identifier: GPL-2.0-only
"""Decoders for SREP Future-LZ and depth-one XTool streams."""
import heapq
import struct
import tempfile

from freearc_inspect import ParseError


def srep_v3(reader, limits):
    from freearc_codecs import Unsupported
    header = reader.exact(16)
    if header[:12] != b'\x17\x18\x35\x26SREP\x03\x01\x00\x00':
        raise Unsupported('requires SREP v3, checksum id 1, 16 reserved checksum bytes')
    base = int.from_bytes(header[12:], 'little')
    pos = 0
    pending = []
    with tempfile.TemporaryFile() as history:
        while True:
            header = reader.read(8)
            if not header or header == bytes(8):
                reader.finish()
                if pending:
                    raise ParseError('SREP references beyond end of output')
                return
            if len(header) != 8:
                raise ParseError('short SREP block header')
            literals, size = struct.unpack('<II', header)
            stats = reader.u32()
            if not 0 < size <= 8 << 20 or literals > size or stats > 16 << 20 or stats % 16:
                raise ParseError('invalid SREP block dimensions')
            if pos+size > limits['intermediate']:
                raise ParseError('SREP history limit exceeded')
            if (len(pending)+stats//16)*192 + size*4 + stats > limits['memory']:
                raise Unsupported('SREP block and reference queue exceed memory limit')
            reader.exact(16)
            source = pos
            save = False
            for gap, distance, length in struct.iter_unpack('<IQI', reader.exact(stats)):
                source += gap
                length += base
                dest = source+distance
                if not distance or not length or source+length > pos+size or dest+length > limits['intermediate']:
                    raise ParseError('invalid SREP forward reference')
                heapq.heappush(pending, (dest, source, length))
                save |= dest >= pos+size
            block = bytearray()
            while pending and pending[0][0] < pos+size:
                dest, source, length = heapq.heappop(pending)
                gap = dest-pos-len(block)
                if gap < 0 or gap > literals or dest+length > pos+size:
                    raise ParseError('invalid or overlapping SREP match')
                block.extend(reader.exact(gap))
                literals -= gap
                if source < pos:
                    count = min(length, pos-source)
                    history.seek(source)
                    earlier = history.read(count)
                    if len(earlier) != count:
                        raise ParseError('missing SREP history')
                    block.extend(earlier)
                    source += count
                    length -= count
                start = source-pos
                while length:
                    count = min(length, len(block)-start)
                    if count <= 0:
                        raise ParseError('invalid SREP match source')
                    block.extend(block[start:start+count])
                    length -= count
            if literals != size-len(block):
                raise ParseError('SREP literal count mismatch')
            block.extend(reader.exact(literals))
            if save:
                history.seek(pos)
                history.write(block)
            pos += size
            for offset in range(0, size, 65536):
                yield bytes(block[offset:offset+65536])


def xtool(reader, memory_limit=256 << 20):
    from freearc_codecs import Unsupported
    if reader.exact(4) != b'XTL0' or reader.u32() != 1:
        raise Unsupported('unsupported XTool magic or nesting depth')
    if reader.exact(reader.byte()) != b'zlib+zstd':
        raise Unsupported('unexpected XTool codec list')
    if reader.u32() or reader.u32() != 0xfffffffe or reader.byte():
        raise Unsupported('unsupported XTool resources, deduplication, or outer compression')
    from freearc_deflate import compress
    pos = 0
    while True:
        if reader.u32():
            raise Unsupported('XTool embedded codec resources')
        count = int.from_bytes(reader.exact(4), 'little', signed=True)
        # XTool DecChunk processes nonnegative counts. Any negative count ends it.
        if count < 0:
            reader.finish()
            return
        size = int.from_bytes(reader.exact(8), 'little', signed=True)
        if size < 0 or count > memory_limit//256 or size > memory_limit:
            raise Unsupported('XTool transformed chunk exceeds memory limit')
        records = list(struct.iter_unpack('<BiiiBI', reader.exact(count*18)))
        if sum(row[2] for row in records) != size:
            raise ParseError('invalid XTool record size total')
        # Transformed payloads precede all interleaved gaps in the wire format.
        with tempfile.SpooledTemporaryFile(max_size=min(memory_limit//8, 8<<20)) as restored:
            for kind, old, new, resource, codec, option in records:
                if min(old,new)<0 or new > memory_limit//8 or old > memory_limit//8:
                    raise Unsupported('invalid or oversized XTool stream')
                if codec != 7 or kind != 0 or option & ~0x3ff8:
                    raise Unsupported(f'XTool record at chunk offset {pos}: codec={codec}, option=0x{option:08x}, kind={kind}, old={old}, new={new}, resource={resource}')
                level, mem = divmod((option >> 3) & 127, 10)
                window = 8+((option >> 10) & 7)
                if not (1 <= level <= 9 and 1 <= mem <= 9 and 9 <= window <= 15):
                    raise Unsupported(f'unsupported XTool DEFLATE properties: {level}, {mem}, {window}')
                compressed = compress(reader.exact(new), level, mem, window)
                if len(compressed) != old:
                    raise Unsupported(f'XTool DEFLATE length mismatch at {pos}: got {len(compressed)}, expected {old} (level={level}, mem={mem}, window={window})')
                restored.write(compressed)
            restored.seek(0)
            for index in range(count+1):
                gap = reader.u32()
                while gap:
                    chunk = reader.exact(min(gap,65536))
                    pos += len(chunk)
                    gap -= len(chunk)
                    yield chunk
                if index<count:
                    left=records[index][1]
                    while left:
                        chunk=restored.read(min(left,65536))
                        if not chunk:
                            raise ParseError('truncated reconstructed XTool record')
                        pos+=len(chunk)
                        left-=len(chunk)
                        yield chunk
