# gop25

A Project 25 (APCO-25) receive stack in Go.

```
import "github.com/raidancampbell/gop25"
```

The package name is `p25`. Phase 2 (H-DQPSK TDMA) lives in the `phase2`
subpackage; the IMBE/AMBE+2 voice codec in `mbe`.

## What's here

- **Phase 1** C4FM symbol recovery and framing
- Forward error correction: BCH, Golay, Hamming, trellis (1/2-rate), Reed-Solomon
- Link control + trunking control (TSBK) decode; RFSS/site following
- SNDCP / PDU data (LRRP, ARS, ICMP/IPv4 payloads)
- IMBE voice decode (via `mbe`)
- **Phase 2** H-DQPSK TDMA (`phase2`)

The decoder is **host-agnostic**: callers implement a small `Host` interface
(logging + grant/discovery callbacks) and feed it post-FM-discriminator
samples. It does not open capture devices, files, or databases.

## Dependencies

- [`github.com/raidancampbell/godsp`](https://github.com/raidancampbell/godsp) — DSP primitives (MIT)

That is the only runtime dependency. Logging goes through the standard
library: `Host.Log()` returns a `*slog.Logger`, so gop25 pulls in no logging
framework of its own. A host that already uses a different logger supplies a
`slog.Handler` that bridges to it.

## License

**GPLv3** — see [LICENSE](LICENSE).

This module is a GPLv3 derivative of prior GPL-licensed work. Portions are
ported from / adapted from:

- **op25** (boatbod / the OP25 project) — control-channel and framing logic
- **jmbe** and **sdrtrunk** (DSheirer) — IMBE/AMBE voice codec and related DSP
- **mbelib** — the IMBE/AMBE+2 vocoder reference implementation

The per-file attribution headers (`// ported from ...`, `// faithful port of
...`) throughout the source are the GPLv3 provenance trail and must be
preserved.

Because gop25 is GPLv3, any program that imports it forms a combined GPLv3 work
when distributed.
