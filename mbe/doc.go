// Package mbe implements the IMBE (P25 Phase 1) and AMBE+2 (P25 Phase 2) voice
// codecs in pure Go: bit unpacking, FEC (Golay/Hamming) error correction,
// parameter decode, and speech synthesis.
//
// It is a faithful port of the mbelib reference decoders (imbe7200x4400.c,
// ambe3600x2450.c). See the per-function "faithful port of" / "translates"
// headers for provenance; the generated coefficient tables live in the
// tables_*.go files.
package mbe
