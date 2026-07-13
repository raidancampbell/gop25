// Package p25 implements a Project 25 (APCO-25) Phase 1 receive stack: C4FM
// symbol recovery and framing, forward error correction (BCH, Golay, Hamming,
// trellis, Reed-Solomon), link-control and trunking-control (TSBK) decode,
// SNDCP/PDU data, and IMBE voice via the mbe subpackage. Phase 2 (H-DQPSK
// TDMA) lives in the phase2 subpackage.
//
// The decoder is host-agnostic: callers supply a Host (see system.go) for
// logging and grant/discovery callbacks and drive it with post-FM-discriminator
// samples. It does not open capture devices, files, or databases.
//
// This package is a GPLv3 derivative of op25 (boatbod), jmbe, and sdrtrunk
// (DSheirer). See the per-file "ported from" / "faithful port of" headers for
// provenance.
package p25
