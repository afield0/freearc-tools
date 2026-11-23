# FreeArc inspector

A separate Python-only extraction implementation is now available; see
[README.extractor.md](README.extractor.md) for supported codecs, tests, and limits.
The inspector below remains read-only and retains its original codec limitations.

Dependency-free, read-only Python CLI targeting Python 3.12+. Also compatible
with Python 3.11 (tested).
It does not extract, execute programs, import archive code, or modify the input.

```powershell
python freearc_inspect.py info archive.bin
python freearc_inspect.py list archive.bin --verbose
python freearc_inspect.py scan archive.bin.filepart
python freearc_inspect.py headers archive.bin.filepart --json
python -m unittest -v test_freearc_inspect
```

By default each command searches the first 64 KiB and last 4096 bytes of the
file size observed at open. Verified footer references can cause additional,
bounded metadata reads. `scan` prints rejected signature candidates and parse
offsets; `headers` prints descriptor details; `info` summarizes; `list` also
prints decoded entries. `--json` returns the full report with any command.

To search a specific region manually:

```powershell
python freearc_inspect.py scan archive.bin.filepart --scan-offset 1048576 --scan-bytes 1048576
```

There is no polling or automatic full-file scan. Large explicitly requested
regions are scanned once in 64 KiB chunks. Reads use 64-bit-capable offsets;
archive size does not determine memory allocation. A metadata block is limited
to 16 MiB, total metadata reads to 32 MiB, entries to 10,000, blocks per index
to 256, signature candidates to 2048, and each string to 64 KiB. These limits
can prevent enumeration of otherwise valid large indexes and are reported.

Windows opens request read access with read/write/delete sharing. An existing
writer that denies shared reading can still prevent opening; that is reported
as an I/O error. Growing files are read only up to their initial size; size and
modification time are checked afterward. This is not an atomic snapshot and
cannot detect every concurrent in-place change. Rerun manually if needed.

Exit codes: **0** recognized inspection completed (not proof of archive
validity/completeness); **2** argument/I/O/read failure; **3** no FreeArc evidence
in searched ranges; **4** truncated signature or incomplete `list` enumeration.
CRC failures and codec/limit problems appear in the report; an `info` or `scan`
exit of 0 does not certify every structure. JSON includes the exit code.

See [FREEARC_FORMAT.md](FREEARC_FORMAT.md) for source references, exact supported
layouts, limitations, and the distinction between real and synthetic tests.
