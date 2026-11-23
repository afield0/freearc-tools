#!/usr/bin/env python3
"""Read-only FreeArc metadata inspector. See FREEARC_FORMAT.md for provenance."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import struct
import sys
import zlib

MAGIC = b'ArC\x01'
TYPES = {0: 'descriptor', 1: 'header', 2: 'data', 3: 'directory',
         4: 'footer', 5: 'recovery'}
MAX_META = 16 * 1024 * 1024
MAX_ITEMS = 10000
MAX_BLOCKS = 256
MAX_CANDIDATES = 2048


class ParseError(ValueError):
    pass


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise ParseError(f'truncated structure at relative offset {self.pos}; need {n} bytes')
        p = self.pos
        self.pos += n
        return self.data[p:self.pos]

    def uint(self):
        first = self.take(1)[0]
        if first == 255:
            return int.from_bytes(self.take(8), 'little')
        n = 1
        while first & (1 << (n - 1)):
            n += 1
        return int.from_bytes(bytes([first]) + self.take(n - 1), 'little') >> n

    def u32(self):
        return int.from_bytes(self.take(4), 'little')

    def string(self):
        end = self.data.find(b'\0', self.pos, self.pos + 65537)
        if end < 0:
            raise ParseError(f'unterminated or oversized string at relative offset {self.pos}')
        raw = self.take(end - self.pos + 1)[:-1]
        # Preserve invalid UTF-8 bytes as surrogate escapes in JSON; never guess an encoding.
        return raw.decode('utf-8', 'surrogateescape')

    def count(self, maximum=MAX_ITEMS):
        n = self.uint()
        if n > maximum or n > len(self.data) - self.pos:
            raise ParseError(f'count {n} exceeds safety limit or available bytes')
        return n

    def boolean(self):
        n = self.take(1)[0]
        if n not in (0, 1):
            raise ParseError('invalid boolean')
        return bool(n)

    def end(self):
        if self.pos != len(self.data):
            raise ParseError(f'unsupported trailing fields at relative offset {self.pos}')


@contextlib.contextmanager
def open_shared(path):
    """Request Windows read/write/delete sharing; never request write access."""
    if os.name != 'nt':
        with open(path, 'rb', buffering=0) as f:
            yield f
        return
    import ctypes
    from ctypes import wintypes
    import msvcrt
    dll = ctypes.WinDLL('kernel32', use_last_error=True)
    create = dll.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = dll.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    handle = create(str(Path(path).absolute()), 0x80000000, 7, None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        close(handle)
        raise
    with os.fdopen(fd, 'rb', buffering=0) as f:
        yield f


class Snapshot:
    def __init__(self, f):
        self.f = f
        self.initial_stat = os.fstat(f.fileno())
        self.size = self.initial_stat.st_size
        self.bytes_read = 0
        self.metadata_bytes = 0

    def read(self, offset, n):
        if offset < 0 or n < 0 or n > MAX_META:
            raise ParseError('invalid read range or read exceeds safety limit')
        self.f.seek(offset)
        left = min(n, max(0, self.size - offset))
        parts = []
        while left:
            chunk = self.f.read(left)
            if not chunk:
                break
            parts.append(chunk)
            left -= len(chunk)
            self.bytes_read += len(chunk)
        return b''.join(parts)

    def payload(self, block):
        n = block['compressed_size']
        if block['method'] != 'storing':
            raise ParseError('unsupported metadata codec: ' + repr(block['method']))
        if n != block['original_size']:
            raise ParseError('storing block has unequal original and compressed sizes')
        if n > MAX_META or self.metadata_bytes + n > 2 * MAX_META:
            raise ParseError('metadata byte budget exceeded')
        self.metadata_bytes += n
        data = self.read(block['offset'], n)
        if len(data) != n:
            raise ParseError('metadata bytes missing from snapshot')
        if zlib.crc32(data) != block['crc32']:
            raise ParseError('metadata payload CRC mismatch (corruption or concurrent modification)')
        return data


def descriptor(data, offset):
    c = Cursor(data)
    if c.take(4) != MAGIC:
        raise ParseError('not a signature')
    typ = c.uint()
    if typ not in TYPES:
        raise ParseError('unknown block type')
    method, original, compressed, crc = c.string(), c.uint(), c.uint(), c.u32()
    crc_end = c.pos
    if c.u32() != zlib.crc32(data[:crc_end]):
        raise ParseError('descriptor CRC mismatch')
    if not original or not compressed or compressed > offset:
        raise ParseError('invalid block size or backward offset')
    return dict(type=TYPES[typ], method=method, original_size=original,
                compressed_size=compressed, crc32=crc, offset=offset - compressed,
                descriptor_offset=offset, descriptor_end=offset + c.pos,
                evidence='descriptor CRC verified')


def footer(data, base):
    c = Cursor(data)
    blocks = []
    # Footer is an array of tuples (AoS), unlike the directory's parallel arrays.
    for _ in range(c.count(MAX_BLOCKS)):
        typ, method, distance = c.uint(), c.string(), c.uint()
        original, compressed, crc = c.uint(), c.uint(), c.u32()
        if typ not in TYPES or distance > base or compressed > distance:
            raise ParseError('invalid footer block reference')
        blocks.append(dict(type=TYPES[typ], method=method, offset=base-distance,
                           original_size=original, compressed_size=compressed,
                           crc32=crc, evidence='verified footer payload'))
    locked = c.boolean()
    old_comment = c.take(c.count() * 4).decode('utf-32-le', 'backslashreplace')
    recovery = c.string() if c.pos < len(data) else None
    comment = c.take(c.count()).decode('utf-8', 'surrogateescape') if c.pos < len(data) else old_comment
    c.end()
    return blocks, dict(locked=locked, recovery_settings=recovery, comment=comment)


def directory(data, base):
    c = Cursor(data)
    n = c.count(MAX_BLOCKS)
    counts = [c.uint() for _ in range(n)]
    total = sum(counts)
    if total > MAX_ITEMS or total > len(data):
        raise ParseError('file count exceeds safety limit or available bytes')
    methods = [c.string() for _ in range(n)]
    distances = [c.uint() for _ in range(n)]
    compressed = [c.uint() for _ in range(n)]
    dirs = [c.string() for _ in range(c.count())]
    names = [c.string() for _ in range(total)]
    indexes = [c.uint() for _ in range(total)]
    sizes = [c.uint() for _ in range(total)]
    times = [c.u32() for _ in range(total)]
    flags = [c.boolean() for _ in range(total)]
    crcs = [c.u32() for _ in range(total)]
    if c.pos < len(data) and c.uint() != 0:
        raise ParseError('unsupported directory extension tag')
    c.end()
    files, solids, i = [], [], 0
    for b in range(n):
        if distances[b] > base or compressed[b] > distances[b]:
            raise ParseError('invalid solid block range')
        solids.append(dict(offset=base-distances[b], compressed_size=compressed[b],
                           method=methods[b], file_count=counts[b]))
        for _ in range(counts[b]):
            if indexes[i] >= len(dirs):
                raise ParseError('invalid directory number')
            parent = dirs[indexes[i]]
            files.append(dict(name=names[i], directory=parent,
                              path=parent + ('' if not parent or parent.endswith(('/', '\\')) else '/') + names[i],
                              original_size=sizes[i], compressed_size=None,
                              solid_block_offset=base-distances[b],
                              solid_compressed_size=compressed[b], method=methods[b],
                              is_directory=flags[i], mtime_raw=times[i], crc32=crcs[i],
                              evidence='CRC-verified directory metadata; file contents not verified'))
            i += 1
    return files, solids


def inspect(path, scan_bytes=65536, scan_offset=0):
    result = dict(path=str(path), archive_complete=False, completeness='not verified',
                  structures=[], candidates=[], files=[], solid_blocks=[], limitations=[],
                  enumeration_complete=False)
    with open_shared(path) as f:
        s = Snapshot(f)
        result['available_bytes'] = s.size
        head = s.read(0, 8)
        result['signature'] = 'confirmed' if head[:4] == MAGIC else (
            'truncated' if len(head) < 4 and MAGIC.startswith(head) else 'not found at offset 0')
        if head[:4] == MAGIC:
            result['header_version_bytes'] = head[4:8].hex(' ')
            if len(head) < 8:
                result['limitations'].append('Header version field truncated; additional bytes required.')
        # Search only explicitly bounded ranges, never automatically sweep a large file.
        ranges = [(scan_offset, min(s.size, scan_offset + scan_bytes)),
                  (max(0, s.size - 4096), s.size)]
        ranges = sorted((a, b) for a, b in ranges if a < b)
        merged = []
        for a, b in ranges:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        result['searched_ranges'] = merged
        seen, stop = set(), False
        for start, end in merged:
            for pos in range(start, end, 65536):
                buf = s.read(pos, min(65536 + 3, end - pos))
                at = buf.find(MAGIC)
                while at >= 0:
                    absolute = pos + at
                    if absolute not in seen and absolute != 0:
                        seen.add(absolute)
                        if len(seen) > MAX_CANDIDATES:
                            result['limitations'].append('signature candidate budget exceeded')
                            stop = True
                            break
                        try:
                            d = descriptor(s.read(absolute, 4096), absolute)
                            result['structures'].append(d)
                        except ParseError as e:
                            result['candidates'].append(dict(offset=absolute, evidence='unconfirmed signature', reason=str(e)))
                    at = buf.find(MAGIC, at + 4)
                if stop:
                    break
            if stop:
                break
        blocks = {(d['offset'], d['type']): d for d in result['structures']}
        footers = [d for d in result['structures'] if d['type'] == 'footer']
        selected = max(footers, key=lambda d: d['descriptor_offset'], default=None)
        indexed_dirs = None
        if selected:
            try:
                refs, result['footer'] = footer(s.payload(selected), selected['offset'])
                result['footer']['descriptor_offset'] = selected['descriptor_offset']
                indexed_dirs = {(d['offset'], d['type']) for d in refs if d['type'] == 'directory'}
                for d in refs:
                    key = (d['offset'], d['type'])
                    if key in blocks:
                        if any(blocks[key][k] != d[k] for k in ('method', 'original_size', 'compressed_size', 'crc32')):
                            raise ParseError('footer and local descriptor disagree')
                for d in refs:
                    key = (d['offset'], d['type'])
                    if key not in blocks:
                        blocks[key] = d
                        result['structures'].append(d)
            except ParseError as e:
                indexed_dirs = None
                result['limitations'].append('footer: ' + str(e))
        else:
            result['limitations'].append('No verified footer found in searched ranges. Complete enumeration requires the footer and directory metadata; these may not have downloaded yet.')
        decoded_dirs = set()
        for key, d in blocks.items():
            if d['type'] not in ('header', 'directory'):
                continue
            try:
                payload = s.payload(d)
                if d['type'] == 'header':
                    if len(payload) != 8 or payload[:4] != MAGIC:
                        raise ParseError('unsupported header payload layout')
                    d['version_bytes'] = payload[4:].hex(' ')
                    d['payload_status'] = 'CRC verified'
                    if d['offset'] == 0:
                        result['header_validated'] = True
                else:
                    entries, solids = directory(payload, d['offset'])
                    if len(result['files']) + len(entries) > MAX_ITEMS:
                        raise ParseError('total file count budget exceeded')
                    result['files'].extend(entries)
                    result['solid_blocks'].extend(solids)
                    decoded_dirs.add(key)
                    d['payload_status'] = 'CRC verified and parsed'
            except ParseError as e:
                d['payload_status'] = str(e)
                result['limitations'].append(f"{d['type']} at {d['offset']}: {e}")
        final_stat = os.fstat(f.fileno())
        result['size_after_inspection'] = final_stat.st_size
        result['changed_during_inspection'] = (final_stat.st_size, final_stat.st_mtime_ns) != (s.size, s.initial_stat.st_mtime_ns)
        result['bytes_read'] = s.bytes_read
        result['enumeration_complete'] = bool(indexed_dirs is not None and indexed_dirs <= decoded_dirs
            and selected['descriptor_end'] == s.size and not result['changed_during_inspection']
            and not str(path).lower().endswith('.filepart') and result.get('header_validated'))
        result['additional_data_required'] = 'unknown' if result['enumeration_complete'] else 'possibly; metadata may be missing, unsupported, or outside searched ranges'
        result['limitations'].append('File data is never decompressed or verified. Archive completeness is never certified. Per-file compressed sizes are not stored for solid blocks.')
        if str(path).lower().endswith('.filepart'):
            result['completeness'] = 'partial download (.filepart); never treated as complete'
        if result['changed_during_inspection']:
            result['limitations'].append('File changed during inspection; this is not an atomic snapshot. Rerun manually.')
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['info', 'list', 'scan', 'headers'])
    p.add_argument('archive')
    p.add_argument('--json', action='store_true', help='machine-readable report')
    p.add_argument('--verbose', action='store_true')
    p.add_argument('--scan-bytes', type=int, default=65536, help='bytes to search (default 65536); tail 4096 also checked')
    p.add_argument('--scan-offset', type=int, default=0)
    a = p.parse_args(argv)
    if a.scan_bytes < 0 or a.scan_offset < 0:
        p.error('scan ranges must be nonnegative')
    try:
        r = inspect(a.archive, a.scan_bytes, a.scan_offset)
    except (OSError, ParseError) as e:
        if a.json:
            print(json.dumps({'error': str(e), 'exit_code': 2}))
        else:
            print(f'Error: {e}', file=sys.stderr)
        return 2
    recognized = r['signature'] == 'confirmed' or bool(r['structures'])
    code = 0 if recognized else 3
    if r['signature'] == 'truncated' or (a.command == 'list' and not r['enumeration_complete']):
        code = 4 if recognized or r['signature'] == 'truncated' else 3
    r['exit_code'] = code
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=True))
    else:
        print(f"Available bytes: {r['available_bytes']:,}; bytes read: {r['bytes_read']:,}")
        print(f"FreeArc signature: {r['signature']}; header validated: {r.get('header_validated', False)}")
        print(f"Completeness: {r['completeness']}")
        print(f"Searched ranges [start,end): {r['searched_ranges']}")
        for d in r['structures']:
            print(f"{d['type']} at {d['offset']}: method={json.dumps(d['method'])}, original={d['original_size']}, compressed={d['compressed_size']}; {d['evidence']}")
            if a.verbose or a.command in ('scan', 'headers'):
                print('  ' + json.dumps(d, ensure_ascii=True))
        print(f"Files decoded: {len(r['files'])}; enumeration complete: {r['enumeration_complete']}")
        print(f"Additional data required: {r['additional_data_required']}")
        if a.command == 'list':
            for entry in r['files']:
                print(json.dumps(entry if a.verbose else {k: entry[k] for k in ('path', 'original_size', 'method', 'compressed_size')}, ensure_ascii=True))
        if a.verbose or a.command == 'scan':
            for c in r['candidates']:
                print('Candidate: ' + json.dumps(c))
        for message in r['limitations']:
            print('Note: ' + message)
    return code


if __name__ == '__main__':
    sys.exit(main())
