# Python FreeArc extraction

`freearc_extract.py` implements an end-to-end **list, test, and extract** workflow
in Python. Its codec implementations, including the LZMA range decoder, are Python
code: no `unarc`, native compression bindings, subprocesses, installer execution,
codec DLLs, or third-party packages. Standard-library filesystem and CRC functions
are used. The tests use the standard-library `lzma` encoder as an independent oracle;
the extractor itself does not import it.

**This is not a universal FreeArc decoder.** It extracts complete archives using
the supported methods below. PPMd, Tornado, GRZip, encryption, and other codecs still
need implementations. Unsupported methods produce a named error; they are never
silently skipped or treated as stored bytes.

## Run

Keep `freearc_extract.py`, `freearc_codecs.py`, `freearc_external.py`, `freearc_deflate.py`, and `freearc_inspect.py` together.
Python 3.12+ is the target; tests also pass on the available Python 3.11.4.

```powershell
python freearc_extract.py list archive.bin
python freearc_extract.py list archive.bin --json
python freearc_extract.py test archive.bin
python freearc_extract.py extract archive.bin
python freearc_extract.py extract archive.bin -d selected --include "docs/*"
```

By default, `archive.bin` extracts to `archive/` beside the input. For an
extensionless input, the folder name ends in `.extracted`. With
`--allow-filepart`, `archive.bin.filepart` also extracts to `archive/`.
Use `-d` or `--destination` to choose another folder.
The destination must **not exist**, and its parent must exist. Output is staged
in a temporary sibling directory. Only after every file's size and CRC, every
decoder's end of stream, and the input's final size/mtime check pass is that
directory renamed into place. Failure or interruption removes staged output.
There is no overwrite/merge mode. File timestamps and explicit directory timestamps
are restored when nonzero; permissions/ACLs are not restored.

`test` writes no extracted files. `--include` selects extraction output, but all files in all
solid blocks are still decoded and CRC-tested. `list` validates the metadata and
reports data methods it cannot decode; listing success does not imply test success.

## Supported codecs

| Method | Implementation and validation |
|---|---|
| `storing` | Streamed copy with exact output lengths and CRCs |
| `lzma` | Raw LZMA1, EOS marker, explicit dictionary/lc/lp/pb settings; Python range coder |
| `rep` | FreeArc REP framing and dictionary/back-reference decoder |
| `delta` | FreeArc table descriptions, column reordering, little-endian delta reconstruction |
| `exe` | Streaming x86 BCJ filter, including cross-buffer state |
| `4x4:<method>` | Version-zero block framing, stored sub-blocks, recursive supported inner method |

Chains such as `rep+lzma`, `delta+lzma`, and `exe+lzma` decode in reverse order.
`4x4` is decoded serially; threading is not necessary for format compatibility.
Encoder-only LZMA parameters are recognized but do not change decoding. Optional
unknown `*` LZMA parameters are ignored according to the source's optional flag.
REP/delta settings affect encoding; their decoding layout is carried in the stream.

Not implemented: `ppmd`, `tor`, `grzip`, `lzp`, `dict`, `mm`, `tta`, `srep`,
`dispack070`, `lzma2`, `tempfile`, encryption, external/plugin codecs, recovery repair, split
volumes, and SFX prefixes. Recovery control blocks may be present in an otherwise
valid archive, but recovery bytes are not repaired or integrity-tested.

## Partial downloads and safe output

`.filepart` is refused by default. To inspect an apparently finished transfer
that retains that name, use:

```powershell
python freearc_extract.py list archive.bin.filepart --allow-filepart --json
```

This flag does **not** enable guessing, partial salvage, or missing metadata.
A CRC-verified final footer at observed EOF, valid referenced descriptors,
decoded directories, and available referenced ranges are still required. The
report keeps `partial_download_name: true`. A successful content test verifies
listed files, not that WinSCP has finished or that the archive is authentic.

Input is opened read-only with Windows read/write/delete sharing. The same handle
is retained throughout. The initial size bounds reads; size/mtime changes cause
failure. This is not an atomic filesystem snapshot and cannot defeat a malicious
writer that restores timestamps. For reliable extraction, finish the transfer first.

Paths are validated before output: traversal, absolute paths, drive/UNC paths,
NTFS alternate streams, Windows device names, trailing-dot/space aliases,
control characters, duplicate names, case collisions, and file/directory conflicts
are rejected. No links are extracted. Existing symlink/reparse parents are rejected.
Use a destination parent you control: the checks are not a sandbox against another
process deliberately replacing directories during extraction. Windows publication
refuses an existing destination; POSIX directory rename additionally assumes no
adversarial concurrent writer in the parent.

## Limits and performance

Defaults:

* 16 MiB per packed/unpacked control block, 32 MiB total decoded metadata.
* 10,000 entries, 256 blocks per metadata index, strings at most 64 KiB.
* 256 MiB large-buffer allowance **per codec stage**, not a total process RSS cap.
  Chains and recursive `4x4` can hold more than one stage's buffers simultaneously.
* 1 TiB total declared output and 1 TiB decoded bytes per intermediate stage.
* At most 16 stages per chain, depth 8, 128 path components.

Use `--max-memory-mib`, `--max-output-bytes`, `--max-intermediate-bytes`, and
`--timeout SECONDS` to adjust runtime limits. A timeout is checked at read/output
boundaries, not enforced by an OS process limit. Disk-space preflight is advisory;
write failures still abort publication. No full archive scan is performed: opening
starts with a bounded tail search and follows verified references.

Offsets use Python integers and data streams use approximately 64 KiB chunks;
archive size does not require loading all data. Block-based codecs retain bounded
individual blocks and dictionaries. A 100+ GB archive is addressable, but the
Python range coder is substantially slower than a native decoder; large archives
can take a long time. No 100 GB throughput claim has been tested.

Exit codes: **0** command succeeded; **2** usage, I/O, unsafe-path, integrity,
incomplete-file, or limit failure; **5** unsupported codec/layout/resource request;
**130** interrupted. JSON runtime results include `exit_code`. Argparse usage errors
use its normal text diagnostics even when `--json` is present.

## Tests and actual demonstration

```powershell
python -m unittest discover -v
python freearc_extract.py test freearc_fixtures/genuine_exe_lzma.arc
# Verified 1 files (262,144 bytes)
python freearc_extract.py extract freearc_fixtures/genuine_delta_lzma.arc -d demo-new
```

Seven upstream fixtures are documented by their producer as generated by the
official FreeArc 0.67 Windows build. They exercise stored data, multiple LZMA
properties, REP, delta, x86 BCJ, and `4x4`. Each downloaded archive was checked
against the upstream Git LFS SHA-256 before use. Tests actually extract every
fixture and verify every file's length and CRC. The `hello.txt` content is also
checked against the independent literal in the upstream input generator. This is
real format interoperability evidence, not solely synthetic parser testing; the
fixture-producing FreeArc executable itself was not run here.

Synthetic tests cover independent LZMA encoder output and chunk boundaries,
overlapping matches, malformed framing, truncation, resource limits, unsafe paths,
collisions, CRC failure cleanup, input mutation, destination preservation,
selection, JSON errors, and `.filepart` handling. The original inspector regression
suite remains included. See [README.md](README.md#tests) for optional fixtures.

## Sources and licensing

* Container references: [FREEARC_FORMAT.md](FREEARC_FORMAT.md).
* [LZMA SDK C_LZMA.cpp](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/LZMA2/C_LZMA.cpp)
  establishes raw range-coded framing, EOS and method-string properties.
* [LZMA SDK LzmaDec.c](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/LZMA2/C/LzmaDec.c),
  Igor Pavlov's public-domain decoder; the LZMA algorithm is implemented in Python here.
* [Bra86.c](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/LZMA2/C/Bra86.c),
  Igor Pavlov, public domain: streaming x86 BCJ algorithm.
* FreeArc by Bulat Ziganshin:
  [REP decoder](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/REP/rep.cpp),
  [delta decoder](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/Delta/Delta.cpp).
* [Compatible 4x4 decoder](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/4x4/C_4x4.cpp).
* [Fixture provenance and generation](https://github.com/n0madic/go-unarc/blob/2236294cc234701a7fb38ddd82f3d26cb83d64a5/testdata/genuine/README.md),
  [independent input generator](https://github.com/n0madic/go-unarc/blob/2236294cc234701a7fb38ddd82f3d26cb83d64a5/scripts/genuine/main.go).
  Local provenance and upstream LFS hashes: `freearc_fixtures/manifest.json`.

The new extraction/codec implementation is provided under GPL-2.0-only, with
upstream algorithm credits retained here; see `LICENSE`.
Additional notices are in [THIRD_PARTY.md](THIRD_PARTY.md).

## SREP and XTool stream variants

The srep_new stage recognizes the observed SREP v3 Future-LZ format with
checksum ID 1 and a reserved 16-byte tag. The decoder checks match boundaries
and reconstructs cross-block references using temporary disk history. An archive
test using this stage can therefore need scratch disk space even in test mode.
The intermediate byte limit also bounds the logical size of the history file.
This variant carries no SREP block hash. Final file integrity uses the FreeArc CRCs.

The XTool stage reads depth-one XTL0 chunks with the embedded method list
zlib+zstd. It reconstructs plain codec-7 raw DEFLATE records using the level,
memory setting, and window size encoded in the record. The Python encoder follows
[zlib 1.2.13](https://github.com/madler/zlib/tree/v1.2.13). It checks the original
compressed length before interleaving each reconstructed stream with the literal
bytes. File CRCs validate the result. Other XTool record types, including actual
Zstandard recompression, patches, embedded resources and nested transforms, raise
an explicit error.

Sources: [SREP v3 reference](https://github.com/n0madic/go-unarc/blob/2236294cc234701a7fb38ddd82f3d26cb83d64a5/internal/codec/srep/srep.go)
and [XTool reader](https://github.com/Razor12911/xtool/blob/9a1d5fafcfd93be25967e6e20734ee05fed07b72/precompressor/PrecompMain.pas).
