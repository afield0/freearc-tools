#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Python-only FreeArc list/test/extract. See README.extractor.md for codec coverage."""
import argparse
import contextlib
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import zlib

import freearc_inspect as fmt
from freearc_codecs import CHUNK, Reader, Unsupported, check_method, decode


class ExtractionError(fmt.ParseError):
    pass


def safe_parts(path):
    """Portable strict paths: reject Windows aliases even when running on Unix."""
    if not path or path.startswith(('/', '\\')):
        raise ExtractionError('empty or absolute archive path: ' + repr(path))
    parts = path.replace('\\', '/').split('/')
    if len(parts) > 128:
        raise ExtractionError('archive path nesting exceeds 128 components')
    for p in parts:
        if (p in ('', '.', '..') or p[-1:] in (' ', '.')
                or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF or c in '<>:"|?*' for c in p)
                or re.fullmatch(r'(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?', p, re.I)):
            raise ExtractionError('unsafe archive path: ' + repr(path))
        if len(p.encode('utf-8')) > 255:
            raise ExtractionError('archive path component too long')
    if len(path) > 4096:
        raise ExtractionError('archive path too long')
    return tuple(parts)


def validate_paths(entries):
    seen = {}
    for e in entries:
        if '/' in e['name'] or '\\' in e['name']:
            raise ExtractionError('archive basename contains path separators')
        parts = safe_parts(e['path'])
        key = tuple(p.casefold() for p in parts)
        if key in seen:
            raise ExtractionError('duplicate or case-colliding archive path: ' + repr(e['path']))
        seen[key] = e['is_directory']
        e['output_parts'] = parts
        if e['is_directory'] and (e['original_size'] != 0 or e['crc32'] != 0):
            raise ExtractionError('directory entry has nonempty content or CRC')
    for key in seen:
        for i in range(1, len(key)):
            if key[:i] in seen and not seen[key[:i]]:
                raise ExtractionError('file/directory path conflict')
    # Implicit parents must also have a single spelling on case-insensitive hosts.
    spellings = {}
    for e in entries:
        parts = e['output_parts']
        for i in range(1, len(parts)+1):
            prefix = parts[:i]
            key = tuple(p.casefold() for p in prefix)
            if key in spellings and spellings[key] != prefix:
                raise ExtractionError('case-colliding parent directory')
            spellings[key] = prefix


def check_destination_parent(parent):
    for p in (parent, *parent.parents):
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
            raise ExtractionError('destination parent contains a symlink or reparse point: ' + str(p))
        if not stat.S_ISDIR(s.st_mode):
            raise ExtractionError('destination parent is not a directory')


class Archive:
    def __init__(self, file, path, limits, allow_filepart=False):
        self.file, self.path, self.limits = file, Path(path), limits
        self.snap = fmt.Snapshot(file)
        self.started = time.monotonic()
        self.control_bytes = 0
        self.entries, self.solids = [], []
        self.footer_info = None
        if self.path.suffix.lower() == '.filepart' and not allow_filepart:
            raise ExtractionError('partial download (.filepart); wait for completion or explicitly use --allow-filepart (a valid final footer is still required)')
        self.read_index()

    def checkpoint(self):
        if self.limits['seconds'] and time.monotonic()-self.started > self.limits['seconds']:
            raise ExtractionError('operation exceeded time limit')

    def unchanged(self):
        now, old = os.fstat(self.file.fileno()), self.snap.initial_stat
        if (now.st_size, now.st_mtime_ns, now.st_ino) != (old.st_size, old.st_mtime_ns, old.st_ino):
            raise ExtractionError('input changed during operation; results not published')

    def chunks(self, offset, size):
        if offset < 0 or size < 0 or offset+size > self.snap.size:
            raise ExtractionError('referenced archive bytes are missing')
        while size:
            self.checkpoint()
            count = min(CHUNK, size)
            chunk = self.snap.read(offset, count)
            if len(chunk) != count:
                raise ExtractionError('short read: archive truncated during operation')
            yield chunk
            offset += count
            size -= count

    def payload(self, block):
        size = block['original_size']
        if max(size, block['compressed_size']) > fmt.MAX_META:
            raise Unsupported('control block exceeds 16 MiB limit')
        self.control_bytes += size
        if self.control_bytes > 2*fmt.MAX_META:
            raise Unsupported('control metadata exceeds 32 MiB budget')
        limits = dict(self.limits, intermediate=fmt.MAX_META)
        data = bytearray()
        for chunk in decode(self.chunks(block['offset'], block['compressed_size']), block['method'], limits):
            self.checkpoint()
            if len(data)+len(chunk) > size:
                raise ExtractionError('metadata output exceeds declared size')
            data.extend(chunk)
        if len(data) != size or zlib.crc32(data) != block['crc32']:
            raise ExtractionError('metadata size or CRC mismatch')
        return bytes(data)

    def read_index(self):
        if self.snap.read(0, 4) != fmt.MAGIC:
            raise ExtractionError('FreeArc signature missing at offset zero; SFX is unsupported')
        start = max(0, self.snap.size-4096)
        tail = self.snap.read(start, 4096)
        candidates = []
        at = tail.find(fmt.MAGIC)
        while at >= 0:
            try:
                d = fmt.descriptor(tail[at:], start+at)
                if d['type'] == 'footer' and d['descriptor_end'] == self.snap.size:
                    candidates.append(d)
            except fmt.ParseError:
                pass
            at = tail.find(fmt.MAGIC, at+4)
        if len(candidates) != 1:
            raise ExtractionError('no unique CRC-verified final footer; archive may be incomplete or corrupt')
        foot = candidates[0]
        blocks, self.footer_info = fmt.footer(self.payload(foot), foot['offset'])
        if not any(b['type'] == 'header' and b['offset'] == 0 for b in blocks):
            raise ExtractionError('footer does not reference the initial archive header')
        intervals = [(foot['offset'], foot['descriptor_end'], 'footer')]
        seen = set()
        for b in blocks:
            key = b['offset']
            if key in seen or not b['original_size'] or not b['compressed_size']:
                raise ExtractionError('duplicate or empty control block reference')
            seen.add(key)
            end = key+b['compressed_size']
            if end > foot['offset']:
                raise ExtractionError('control block overlaps footer')
            # Cross-check each indexed local descriptor instead of trusting an offset alone.
            local = fmt.descriptor(self.snap.read(end, 4096), end)
            for k in ('type', 'offset', 'method', 'original_size', 'compressed_size', 'crc32'):
                if local[k] != b[k]:
                    raise ExtractionError('footer reference disagrees with local descriptor')
            intervals.append((key, local['descriptor_end'], b['type']))
            if b['type'] == 'header':
                data = self.payload(b)
                if key != 0 or len(data) != 8 or data[:4] != fmt.MAGIC:
                    raise Unsupported('unsupported archive header layout')
                self.version = data[4:].hex(' ')
            elif b['type'] == 'directory':
                entries, solids = fmt.directory(self.payload(b), key)
                if len(self.entries)+len(entries) > fmt.MAX_ITEMS:
                    raise Unsupported('file count exceeds 10000 limit')
                index = 0
                for solid in solids:
                    group = entries[index:index+solid['file_count']]
                    index += solid['file_count']
                    solid['entries'] = group
                    solid['original_size'] = sum(e['original_size'] for e in group)
                    self.solids.append(solid)
                    if solid['compressed_size']:
                        intervals.append((solid['offset'], solid['offset']+solid['compressed_size'], 'solid'))
                self.entries.extend(entries)
            elif b['type'] not in ('recovery', 'footer'):
                raise Unsupported('unsupported indexed control block: ' + b['type'])
        intervals.sort()
        for left, right in zip(intervals, intervals[1:]):
            if left[1] > right[0]:
                raise ExtractionError('overlapping archive block ranges')
        validate_paths(self.entries)
        self.unchanged()

    def report(self):
        unsupported = []
        for b in self.solids:
            try:
                check_method(b['method'], self.limits)
            except Unsupported as e:
                unsupported.append(str(e))
        return dict(path=str(self.path), available_bytes=self.snap.size,
                    header_version_bytes=self.version, files=self.entries,
                    file_count=sum(not e['is_directory'] for e in self.entries),
                    original_bytes=sum(e['original_size'] for e in self.entries),
                    data_methods=sorted({b['method'] for b in self.solids}),
                    unsupported=sorted(set(unsupported)),
                    metadata_validated=True, file_contents_verified=False,
                    partial_download_name=self.path.suffix.lower() == '.filepart')

    def process(self, destination=None, includes=()):
        # Preflight every codec and output before creating any files.
        for solid in self.solids:
            check_method(solid['method'], self.limits)
        total = sum(e['original_size'] for e in self.entries)
        if total > self.limits['output']:
            raise ExtractionError('declared output exceeds --max-output-bytes')
        def selected(e):
            return not includes or any(fnmatch.fnmatchcase('/'.join(e['output_parts']), p) for p in includes)
        selected_size = sum(e['original_size'] for e in self.entries if selected(e))
        dest = Path(os.path.abspath(destination)) if destination is not None else None
        if dest:
            if os.path.lexists(dest):
                raise ExtractionError('destination already exists; choose a new directory')
            check_destination_parent(dest.parent)
            if shutil.disk_usage(dest.parent).free < selected_size:
                raise ExtractionError('insufficient free space for declared output')
        with contextlib.ExitStack() as stack:
            stage = None
            if dest:
                temp = stack.enter_context(tempfile.TemporaryDirectory(prefix='.freearc-', dir=dest.parent))
                stage = Path(temp)/'output'
                stage.mkdir(mode=0o700)
            verified = 0
            for solid in self.solids:
                self.checkpoint()
                r = Reader(decode(self.chunks(solid['offset'], solid['compressed_size']), solid['method'], self.limits))
                for e in solid['entries']:
                    target = stage.joinpath(*e['output_parts']) if stage and selected(e) else None
                    if e['is_directory']:
                        if target:
                            target.mkdir(parents=True, exist_ok=True, mode=0o700)
                        continue
                    if target:
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    sink = open(target, 'xb') if target else contextlib.nullcontext(None)
                    with sink as out:
                        left, crc = e['original_size'], 0
                        while left:
                            self.checkpoint()
                            chunk = r.exact(min(left, CHUNK))
                            left -= len(chunk)
                            crc = zlib.crc32(chunk, crc)
                            if out:
                                out.write(chunk)
                    if crc != e['crc32']:
                        raise ExtractionError('file CRC mismatch: ' + repr(e['path']))
                    if target and e['mtime_raw']:
                        os.utime(target, (e['mtime_raw'], e['mtime_raw']))
                    verified += 1
                r.finish()  # Consume end markers and reject excess decoded data.
            if stage:
                for e in sorted(self.entries, key=lambda e: len(e['output_parts']), reverse=True):
                    if e['is_directory'] and selected(e) and e['mtime_raw']:
                        target = stage.joinpath(*e['output_parts'])
                        os.utime(target, (e['mtime_raw'], e['mtime_raw']))
            self.unchanged()
            if dest:
                check_destination_parent(dest.parent)
                if os.path.lexists(dest):
                    raise ExtractionError('destination appeared during extraction; refusing publication')
                # Windows rename never replaces an existing destination directory.
                # POSIX requires a parent not writable by an adversarial concurrent process.
                os.rename(stage, dest)
            return dict(verified_files=verified, verified_bytes=total,
                        extracted_files=sum(not e['is_directory'] and selected(e) for e in self.entries) if dest else 0,
                        extracted_bytes=selected_size if dest else 0,
                        destination=str(dest) if dest else None,
                        file_contents_verified=True,
                        partial_download_name=self.path.suffix.lower() == '.filepart')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    aliases = {'x': 'extract', 'l': 'list', 't': 'test'}
    p.add_argument('command', choices=(*aliases.values(), *aliases),
                   help=', '.join(f'{name} ({short})' for short, name in aliases.items()))
    p.add_argument('archive')
    p.add_argument('-d', '--destination', help='new output directory (default: beside the archive, named after its stem)')
    p.add_argument('-i', '--include', action='append', default=[], help='output glob; all files are still CRC-tested')
    p.add_argument('-f', '--allow-filepart', action='store_true', help='permit a .filepart name only if final footer and referenced data are present')
    p.add_argument('-j', '--json', action='store_true')
    p.add_argument('-m', '--max-memory-mib', type=int, default=256, help='large-buffer limit per codec stage')
    p.add_argument('-o', '--max-output-bytes', type=int, default=1024**4)
    p.add_argument('-b', '--max-intermediate-bytes', type=int, default=1024**4)
    p.add_argument('-t', '--timeout', type=float, default=0, help='seconds; 0 disables deadline')
    args = p.parse_args(argv)
    args.command = aliases.get(args.command, args.command)
    if args.command != 'extract' and (args.destination or args.include):
        p.error('--destination and --include apply only to extract')
    if min(args.max_memory_mib, args.max_output_bytes, args.max_intermediate_bytes) <= 0 or args.timeout < 0:
        p.error('limits must be positive; timeout must be nonnegative')
    limits = dict(memory=args.max_memory_mib*1024**2, output=args.max_output_bytes,
                  intermediate=args.max_intermediate_bytes, seconds=args.timeout)
    try:
        with fmt.open_shared(args.archive) as f:
            archive = Archive(f, args.archive, limits, args.allow_filepart)
            if args.command == 'extract' and args.destination is None:
                path = archive.path
                base = path.with_suffix('') if path.suffix.lower() == '.filepart' else path
                name = base.stem
                if name in ('.', '..', path.name):
                    name = path.name + '.extracted'
                args.destination = path.with_name(name)
            result = archive.report() if args.command == 'list' else archive.process(args.destination, args.include)
        result['exit_code'] = 0
    except Unsupported as e:
        result = dict(error=str(e), exit_code=5)
    except (OSError, fmt.ParseError) as e:
        result = dict(error=str(e), exit_code=2)
    except KeyboardInterrupt:
        result = dict(error='interrupted; staged output discarded', exit_code=130)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    elif 'error' in result:
        print('Error: ' + result['error'], file=sys.stderr)
    elif args.command == 'list':
        for e in result['files']:
            print(f"{e['original_size']:>14}  {json.dumps(e['path'])}  {json.dumps(e['method'])}")
        print(f"{result['file_count']} files; {result['original_bytes']:,} original bytes")
        for issue in result['unsupported']:
            print('Unsupported: ' + issue)
    else:
        print(f"Verified {result['verified_files']} files ({result['verified_bytes']:,} bytes)")
        if result['destination']:
            print(f"Extracted {result['extracted_files']} files to {result['destination']}")
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
