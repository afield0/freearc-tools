# FreeArc tools

**Pure Python, standard library only.** Inspect, verify, and extract supported FreeArc archives with Python 3.11 or later. All included codecs are implemented in Python. There are no third-party packages to install.

## Extract an archive

From the project directory, pass the path to your FreeArc archive:

```sh
python freearc_extract.py extract "downloads/archive.bin"
```

This creates `downloads/archive/` after every file passes its size and CRC32 checks. To choose a different folder, add `-d unpacked`. If the destination already exists, extraction stops.

To try it with the included FreeArc 0.67 archive, run the command below. It creates `extracted/bin/x86.bin` (262,144 bytes).

```sh
python freearc_extract.py extract freearc_fixtures/genuine_exe_lzma.arc -d extracted
```

## Inspect or verify

```sh
python freearc_extract.py list archive.bin
python freearc_extract.py test archive.bin
```

`list` shows the archive directory. `test` verifies file sizes and CRC32s without keeping extracted files.

For a growing download, the inspector can report a validated header before the directory arrives.

```sh
python freearc_inspect.py scan archive.bin.filepart
python freearc_inspect.py headers archive.bin.filepart --json
python freearc_inspect.py list archive.bin --verbose
```

## Format support

| Feature | Implemented | Limits |
| --- | --- | --- |
| Read-only inspection | Header and descriptor CRCs, stored footers and directories, bounded scans with offsets, Windows shared reads | A partial download may have no filenames yet. The inspector labels it partial. |
| Archive listing | Paths, sizes, timestamps, file CRCs, solid-block sizes and methods. The extractor also reads metadata compressed with supported codecs. | Compressed sizes belong to solid blocks. Individual file compressed sizes are unavailable. |
| Testing and extraction | Per-file CRC32 and size checks, safe relative paths, optional output selection, JSON reports | Requires the final footer and all referenced data. Selecting files still requires decoding and verifying the solid blocks. |
| FreeArc codecs | Stored data, raw LZMA1, REP, delta, x86 BCJ (`exe`), version-zero `4x4` with supported inner methods, and chains of supported stages | PPMd, Tornado, GRZip, LZMA2 and other unlisted codecs are unsupported. |
| SREP | `srep_new` v3 Future-LZ with checksum ID 1 and the supported header layout | Other SREP formats are unsupported. History can require substantial temporary disk space, including during verification. |
| XTool | `xtool:mzlib:mzstd` depth-one XTL0 literal data and plain codec-7 raw DEFLATE reconstruction | Zstandard records, patches, embedded resources and nested transforms are unsupported. A declared method list alone cannot establish extractability. |
| Other archive features | Read-only archive access | No archive creation, encryption, split volumes, SFX extraction, recovery repair or partial-file salvage. |

The [inspector guide](README.freearc.md) covers scan ranges and partial downloads. The [extractor guide](README.extractor.md) covers limits, exit codes, and codec parameters. The [format notes](FREEARC_FORMAT.md) describe the wire structures and their upstream sources.

## Tests

```sh
python -m unittest discover -v
```

The offline suite includes three FreeArc-produced archives with generated binary payloads. The tests verify the fixture hashes, extract their contents, and check sizes and CRCs. Synthetic tests exercise malformed input, partial downloads, path handling, and additional codec variants.

Four optional upstream fixtures cover stored files, small-dictionary LZMA, REP and 4x4. Their payloads include upstream source excerpts. To run those cases, check out go-unarc revision `2236294cc234701a7fb38ddd82f3d26cb83d64a5` with Git LFS, set `FREEARC_TEST_FIXTURES` to its `testdata/genuine/archives` directory, and rerun the suite. Without that setting the four missing cases are reported as skipped. [Fixture manifest](freearc_fixtures/manifest.json) · [Upstream generation notes](https://github.com/n0madic/go-unarc/blob/2236294cc234701a7fb38ddd82f3d26cb83d64a5/testdata/genuine/README.md)

## License

The combined tools are distributed under GPL-2.0-only. Component licenses and upstream credits are documented separately. [License](LICENSE) · [Third-party notices](THIRD_PARTY.md)
