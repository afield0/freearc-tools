# Third-party notices

The combined extractor carries the existing GPL-2.0-only designation. This project implements FreeArc and compatible decoder behavior in Python. The source references below document the implementation lineage.

| Component | Origin and terms |
| --- | --- |
| Container, REP, delta and 4x4 | FreeArc by Bulat Ziganshin and compatible unarc sources. The [format notes](FREEARC_FORMAT.md) and [extractor guide](README.extractor.md#sources-and-licensing) identify the relevant routines. The Python extractor and codec modules carry GPL-2.0-only notices. |
| SREP and archive fixtures | The SREP implementation used the [go-unarc decoder](https://github.com/n0madic/go-unarc/blob/2236294cc234701a7fb38ddd82f3d26cb83d64a5/internal/codec/srep/srep.go) as a format reference. The bundled FreeArc 0.67 test archives come from the same [GPL-2.0 project](https://github.com/n0madic/go-unarc/tree/2236294cc234701a7fb38ddd82f3d26cb83d64a5). Their upstream names, revision, and hashes are recorded in the [manifest](freearc_fixtures/manifest.json). |
| LZMA1 and x86 BCJ | Based on the public-domain LZMA SDK algorithms by Igor Pavlov. [Decoder](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/LZMA2/C/LzmaDec.c) · [BCJ filter](https://github.com/Helaas/unarc/blob/70cd3eb3f1b08feb499a2f4f53c739229aaf86ee/Compression/LZMA2/C/Bra86.c) |
| XTool record handling | Based on the [XTool format implementation](https://github.com/Razor12911/xtool/tree/9a1d5fafcfd93be25967e6e20734ee05fed07b72), distributed under the [MIT license](LICENSE.xtool). |
| DEFLATE recompression | The Python encoder is an altered implementation based on zlib 1.2.13 by Jean-loup Gailly and Mark Adler. Retain the [zlib notice](LICENSE.zlib). [Upstream source](https://github.com/madler/zlib/tree/v1.2.13) |
