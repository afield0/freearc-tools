# Supported FreeArc structures and evidence

Research was performed before implementation, on 2026-11-22. Sources consulted:

1. Bulat Ziganshin's [FreeArc archive format notes](https://github.com/Bulat-Ziganshin/FA/blob/master/FreeArc-archive-format.md).
2. Original FreeArc source mirror: [ArhiveStructure.hs](https://github.com/svn2github/freearc/blob/master/ArhiveStructure.hs),
   particularly `archiveWriteHeaderBlock`, `archiveReadBlockDescriptor`,
   `archiveWriteFooterBlock`, `blockToTuple`, and the `BlockType` instance.
3. [ByteStream.hs](https://github.com/svn2github/freearc/blob/master/ByteStream.hs):
   `FastBufferData Integer`, tuple/list serialization and UTF-8 strings.
4. [ArhiveDirectory.hs](https://github.com/svn2github/freearc/blob/master/ArhiveDirectory.hs):
   `archiveWriteDir` and `archiveReadDir`.
5. Compatible [Helaas/unarc ArcStructure.h, pinned revision](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/ArcStructure.h):
   `MEMORY_BUFFER::readInteger`, `LOCAL_BLOCK_DESCRIPTOR`, `ARCHIVE::read_structure`,
   and `DIRECTORY_BLOCK::DIRECTORY_BLOCK`.
6. [Options.hs](https://github.com/svn2github/freearc/blob/master/Options.hs):
   the historical `aARCHIVE_VERSION = make4byte 0 0 5 9` constant. The inspector reports the four version bytes verbatim.

## Wire encoding

Unsigned integers use FreeArc's little-endian 1–9 byte encoding, **not LEB128**.
For widths 1–8, the first byte has width−1 low one-bits followed by a zero;
read that many bytes and right-shift by the width. `ff` introduces a separate
8-byte unsigned integer. CRCs and timestamps are fixed 32-bit little-endian.
Strings are NUL-terminated UTF-8. Invalid UTF-8 bytes are preserved with
surrogate escapes in JSON, without guessing a legacy encoding. Booleans are bytes.

The high-level notes describe block types as one byte, but both implementations
actually use the integer codec: header=1 is encoded `02`, data=2 as `04`,
directory=3 as `06`, footer=4 as `08`, recovery=5 as `0a`. Implementation evidence
takes precedence over the shorthand description.

## Implemented

* Header payload: four signature bytes `41 72 43 01` followed by four version
  bytes. Signature recognition alone is weak evidence. A validated header needs
  a verified descriptor, exact 8-byte payload, matching signature, and payload CRC.
* Local descriptor: signature, encoded block type, method string, encoded original
  size, encoded compressed size, payload CRC32, descriptor CRC32. Descriptor CRC
  covers everything from its signature through the payload CRC. The block begins
  at `descriptor_offset - compressed_size`. Descriptor length is determined by
  parsing, not guessed from a fixed byte offset. At most 4096 bytes are examined
  for each candidate, matching the original footer search bound.
* Stored metadata (`storing`): bounded read, equal compressed/original sizes,
  CRC check before interpretation. Other method strings are reported as declared
  by a verified descriptor; this does not confirm that a decoder supports them.
* Footer payload: encoded tuple count, then **array of tuples**, each containing
  type, method, backward distance from footer payload start, original size,
  compressed size, CRC32. Then locked byte, legacy comment count and UTF-32LE
  characters, optional recovery-settings string, optional UTF-8 comment byte
  count and bytes. Contrary to the broad struct-of-arrays wording in the notes,
  the footer's tuple list is AoS in both inspected implementations.
* Directory payload: solid-block count; parallel arrays of file counts, method
  strings, backward distances from directory start, compressed sizes; directory
  name count and strings; parallel arrays of basenames, directory indexes,
  original sizes, timestamps, directory flags, file CRC32s. File count is the sum
  of solid-block file counts. A zero extension terminator or historical end of
  payload is accepted; unknown trailing fields are rejected.

Paths are displayed as metadata, never resolved against the filesystem. The
directory and basename are also reported separately. Compressed sizes belong
to **solid blocks**, so per-file `compressed_size` is null. No proportional
estimate is substituted. File methods are available only after decoding a
verified directory; a header's method is never applied to files.

## Incomplete and unsupported cases

Directories normally follow the solid blocks they describe. The final footer
locates control blocks; it is not assumed to be at the beginning. Recovery data
may introduce another footer. The latest discovered verified footer is used;
earlier or isolated directories may still yield a partial listing. Searching
only bounded regions cannot establish absence of metadata elsewhere.

`enumeration_complete` means that the selected footer ends at the observed EOF,
its listed directories decoded, a header at offset zero validated, no observed
file change occurred, and the name does not end in `.filepart`. It is a metadata
assessment only. `archive_complete` always remains false: no file-data CRCs,
compressed streams, recovery information or expected download length are checked.
A `.filepart` is always explicitly labeled partial even when a footer is present.

Unsupported: compressed/encrypted metadata, FreeArc codec chains, recovery/ECC
decoding, unknown directory extensions, oversized indexes, full SFX validation,
split volumes, and file extraction/testing. Arbitrary data can contain matching
signature bytes; failed descriptor candidates are labeled unconfirmed and never
used to infer file names. CRC verification detects accidental damage, not forgery.

The standard library has some related codecs, but their framing and parameters
are not interchangeable with FreeArc's named compressor chains. This version
does not attempt to feed arbitrary FreeArc `lzma` bytes into `lzma.decompress`.
No external unarc integration is included; it is optional in the requested scope.
Consequently the CLI has no code path that launches an executable or DLL.

## Validation boundary

Update: the separate extractor now decodes seven pinned FreeArc-produced fixtures,
including compressed metadata and file contents. See [README.extractor.md](README.extractor.md).
The following paragraphs describe the original inspector's validation scope.

The header regression fixture is generated from synthetic fields. Independent upstream archives exercise real header parsing.

Synthetic tests implement the documented/source-confirmed stored directory and
footer formats, exercise listing, truncations at every header byte, all integer
widths, malformed counts, CRC failures, unsupported methods, high offsets,
read/write sharing, growth and shrinkage, randomized malformed data, and JSON
exit codes. The extractor interoperability tests use archives produced by FreeArc 0.67. See [the test instructions](README.md#tests).
