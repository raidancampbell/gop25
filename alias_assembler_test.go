package p25

import (
	"testing"
)

// TestAliasAssembler verifies the Phase 1 talker-alias reassembler via synthetic
// round-trip oracles (Motorola + Harris). References:
//   - sdrtrunk LCMotorolaTalkerAliasAssembler.java (Motorola state machine)
//   - sdrtrunk LCHarrisTalkerAliasComplete.java (Harris assembly)

// TestAliasAssembler_Motorola synthesizes a valid [SUID|alias|CRC] buffer,
// chunks it into header + data blocks (the INVERSE of the assembler's bit
// extraction), drives them through the assembler, and asserts the round-trip
// closes (returned alias == MotorolaAliasDecode(buffer), tg correct, complete
// only after the last block). Also checks sequence-mismatch rejection.
func TestAliasAssembler_Motorola(t *testing.T) {
	// Build a valid Motorola alias buffer: 7-byte SUID + encoded alias + 2-byte CRC.
	// For test simplicity, zero SUID, and a short ASCII-range alias that survives
	// the Motorola obfuscation round-trip (we defer semantic correctness to live).
	suid := make([]byte, 7) // all zeros
	// Use a simple ASCII test string: "TEST" (4 chars = 8 bytes after obfuscation).
	// We'll encode it backward (run MotorolaAliasDecode's inverse), but for the
	// test we'll trust that MotorolaAliasDecode is the oracle and just build a
	// buffer that passes CRC.
	// Simple stub: put raw UTF-16 code units for "TEST" in big-endian byte pairs:
	// T=0x0054 E=0x0045 S=0x0053 T=0x0054 -> 8 bytes + CRC.
	// Actually the aliasBytes must pass the obfuscation; for minimal friction,
	// we'll let MotorolaAliasDecode be the oracle and build a buffer by hand:
	// Use zero bytes for the alias portion and let CRC cover it (degenerate but valid).
	// Let's actually make a real valid buffer: 7-byte SUID, 2-byte alias (1 char),
	// 2-byte CRC. Total 11 bytes = 88 bits = 2 data blocks (44 bits each).
	aliasBytes := []byte{0x00, 0x41} // 1 char: 'A' as UTF-16 0x0041
	payload := append(suid, aliasBytes...)
	crc := CRC16GSM(payload)
	buf := append(payload, byte(crc>>8), byte(crc&0xFF))
	if len(buf) != 11 {
		t.Fatalf("want 11-byte buffer, got %d", len(buf))
	}

	const seq = 7
	const tg = 0x1234
	hdr, blocks := packMotoBlocks(t, seq, tg, buf)

	// Verify packMotoBlocks produced the right number of blocks (88 bits / 44 = 2).
	if len(blocks) != 2 {
		t.Fatalf("want 2 blocks for 88-bit buffer, got %d", len(blocks))
	}

	var a aliasAssembler

	// Feed header: should latch state but not complete.
	alias1, tg1, _, complete1 := a.addMotorolaHeader(hdr)
	if complete1 {
		t.Fatalf("header must not complete")
	}
	if alias1 != "" || tg1 != 0 {
		t.Errorf("header: want empty alias/tg=0, got %q / %d", alias1, tg1)
	}

	// Feed first data block: still not complete.
	alias2, tg2, _, complete2 := a.addMotorolaBlock(blocks[0])
	if complete2 {
		t.Fatalf("first block must not complete")
	}
	if alias2 != "" || tg2 != 0 {
		t.Errorf("block 1: want empty alias/tg=0, got %q / %d", alias2, tg2)
	}

	// Feed second (last) data block: must complete now.
	alias3, tg3, _, complete3 := a.addMotorolaBlock(blocks[1])
	if !complete3 {
		t.Fatalf("final block must complete, got false")
	}
	if tg3 != tg {
		t.Errorf("tg: want 0x%04x, got 0x%04x", tg, tg3)
	}

	// The returned alias must match MotorolaAliasDecode(buf).
	want, _, ok := MotorolaAliasDecode(buf)
	if !ok {
		t.Fatalf("oracle MotorolaAliasDecode failed on synthetic buffer (CRC issue?)")
	}
	if alias3 != want {
		t.Errorf("alias round-trip: want %q, got %q", want, alias3)
	}

	// Subsequent calls must NOT re-emit (complete=false).
	alias4, _, _, complete4 := a.addMotorolaBlock(blocks[1])
	if complete4 {
		t.Errorf("re-feed last block: want complete=false (no re-emit), got true")
	}
	if alias4 != "" {
		t.Errorf("re-feed: want empty alias, got %q", alias4)
	}

	// Feed a block with a WRONG sequence: must be ignored (assembler resets on mismatch).
	var aSeq aliasAssembler
	aSeq.addMotorolaHeader(hdr)
	aSeq.addMotorolaBlock(blocks[0])
	// Craft a second block with a different sequence.
	badBlock := blocks[1]
	badBlock[3] = (badBlock[3] & 0x0F) | 0x50 // change seq nibble from 7 to 5
	alias5, _, _, complete5 := aSeq.addMotorolaBlock(badBlock)
	if complete5 {
		t.Errorf("sequence mismatch: must ignore bad block, got complete=true")
	}
	if alias5 != "" {
		t.Errorf("sequence mismatch: want empty alias, got %q", alias5)
	}
}

// TestAliasAssembler_MotorolaTrimRetry exercises the trim-retry path: when the
// concatenated fragments pack to a buffer with trailing zero PAD beyond the real
// [SUID|alias|CRC] (the common case, since fragment bit-length rarely divides
// evenly), the assembler must trim trailing zero bytes and re-decode until the
// CRC validates. Here a valid 11-byte buffer is forced into 3 data blocks
// (132 bits = 16 bytes packed), leaving 5 trailing zero bytes to be trimmed.
func TestAliasAssembler_MotorolaTrimRetry(t *testing.T) {
	suid := make([]byte, 7)
	aliasBytes := []byte{0x00, 0x41} // 1 char
	payload := append(suid, aliasBytes...)
	crc := CRC16GSM(payload)
	validBuf := append(payload, byte(crc>>8), byte(crc&0xFF)) // 11 bytes, valid CRC

	// Append 2 zero bytes so packMotoBlocks needs 3 blocks (104 -> 132 bits),
	// producing a 16-byte reassembled buffer with 5 trailing zero pad bytes.
	padded := append(append([]byte{}, validBuf...), 0x00, 0x00)

	const seq = 3
	const tg = 0x0ABC
	hdr, blocks := packMotoBlocks(t, seq, tg, padded)
	if len(blocks) != 3 {
		t.Fatalf("want 3 blocks for padded buffer, got %d", len(blocks))
	}

	var a aliasAssembler
	a.addMotorolaHeader(hdr)
	var alias string
	var gotTG uint16
	var complete bool
	for i, b := range blocks {
		alias, gotTG, _, complete = a.addMotorolaBlock(b)
		if i < len(blocks)-1 && complete {
			t.Fatalf("block %d: completed early", i)
		}
	}
	if !complete {
		t.Fatal("trim-retry: assembler never completed (trim path failed to recover valid CRC)")
	}
	if gotTG != tg {
		t.Errorf("trim-retry tg: want 0x%04x, got 0x%04x", tg, gotTG)
	}
	want, _, ok := MotorolaAliasDecode(validBuf)
	if !ok {
		t.Fatal("oracle failed on the 11-byte valid buffer")
	}
	if alias != want {
		t.Errorf("trim-retry alias: want %q, got %q", want, alias)
	}
}

// TestAliasAssembler_Harris feeds LCO 50/51 (blocks 1+2) with ASCII payloads,
// asserts completion after block 2, and checks the result matches harrisAliasString.
func TestAliasAssembler_Harris(t *testing.T) {
	// LCO 50 = block 1 (position 0), LCO 51 = block 2 (position 1).
	// Payload = bytes 2-8 (7 ASCII chars each).
	lcw1 := [9]byte{
		0x32, 0xA4, // LCO=50 MFID=0xA4 (Harris)
		'E', 'N', 'G', 'I', 'N', 'E', ' ', // "ENGINE "
	}
	lcw2 := [9]byte{
		0x33, 0xA4, // LCO=51
		'1', '2', ' ', 'C', 'A', 'P', 'T', // "12 CAPT"
	}

	var a aliasAssembler

	// Feed block 1: not complete yet.
	alias1, tg1, _, complete1 := a.addHarris(lcw1)
	if complete1 {
		t.Fatalf("Harris block 1 must not complete")
	}
	if alias1 != "" || tg1 != 0 {
		t.Errorf("Harris block 1: want empty alias/tg=0, got %q / %d", alias1, tg1)
	}

	// Feed block 2: must complete now.
	alias2, tg2, _, complete2 := a.addHarris(lcw2)
	if !complete2 {
		t.Fatalf("Harris block 2 must complete, got false")
	}
	if tg2 != 0 {
		t.Errorf("Harris tg: want 0, got %d", tg2)
	}

	// The returned alias must match HarrisAliasString([block1_payload, block2_payload]).
	want := HarrisAliasString([][]byte{lcw1[2:], lcw2[2:]})
	if alias2 != want {
		t.Errorf("Harris alias: want %q, got %q", want, alias2)
	}

	// Subsequent calls must NOT re-emit.
	alias3, _, _, complete3 := a.addHarris(lcw2)
	if complete3 {
		t.Errorf("re-feed Harris block 2: want complete=false, got true")
	}
	if alias3 != "" {
		t.Errorf("re-feed Harris: want empty alias, got %q", alias3)
	}
}

func TestAddHarrisGPSBlock_TwoBlocks(t *testing.T) {
	// Build a known 112-bit Harris GPS field, then split it across two LCWs:
	// block 1 (LCO=42) carries field bits[0:56] in its bytes 2-8, block 2
	// (LCO=43) carries field bits[56:112]. Decoding the reassembly must match a
	// direct DecodeHarrisGPS of the same field.
	field := make([]uint8, 112)
	packBits(field, 0, 16, 5000)  // lat frac
	packBits(field, 17, 7, 45)    // lat minutes
	packBits(field, 24, 8, 39)    // lat degrees
	field[48] = 1                 // lon hemisphere negative
	packBits(field, 49, 7, 30)    // lon minutes
	packBits(field, 56, 8, 104)   // lon degrees
	packBits(field, 95, 9, 270)   // heading

	want, ok := DecodeHarrisGPS(field)
	if !ok {
		t.Fatalf("reference DecodeHarrisGPS(field) ok=false")
	}

	fieldBytes := bitsToBytes(field) // 14 bytes
	lcw1 := [9]byte{0x2A, 0xA4}      // LCO=42 MFID=0xA4
	copy(lcw1[2:], fieldBytes[0:7])
	lcw2 := [9]byte{0x2B, 0xA4} // LCO=43
	copy(lcw2[2:], fieldBytes[7:14])

	var a aliasAssembler

	if _, complete := a.addHarrisGPSBlock(0x2A, lcw1); complete {
		t.Fatalf("Harris GPS block 1 must not complete")
	}
	got, complete := a.addHarrisGPSBlock(0x2B, lcw2)
	if !complete {
		t.Fatalf("Harris GPS block 2 must complete")
	}
	if got != want {
		t.Errorf("reassembled GPS = %+v, want %+v", got, want)
	}

	// Re-feed must not re-emit.
	if _, complete := a.addHarrisGPSBlock(0x2B, lcw2); complete {
		t.Errorf("re-feed block 2: want complete=false")
	}
}

// packMotoBlocks is the INVERSE of the assembler's bit extraction. Given a
// buffer (typically [SUID(7B)|aliasBytes|CRC16(2B)], optionally with trailing
// pad to exercise the trim-retry path), it chunks the buffer MSB-first into
// 44-bit fragments and builds a header LCW + data-block LCWs (LCO=0x15 / 0x17,
// MFID=0x90). Packing is purely mechanical and does not require a valid CRC;
// callers assert decode validity where it matters.
func packMotoBlocks(t *testing.T, seq int, tg uint16, buf []byte) (hdr [9]byte, blocks [][9]byte) {
	t.Helper()

	// Expand buffer to MSB-first bit slice.
	bufBits := make([]uint8, len(buf)*8)
	for i, b := range buf {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<(7-bit)) != 0 {
				bufBits[i*8+bit] = 1
			}
		}
	}

	nBits := len(bufBits)
	nBlocks := (nBits + 43) / 44 // ceiling division

	// Build header: LCO=0x15, MFID=0x90, TG@bytes2-3, BLOCK_COUNT@byte4,
	// FORMAT=1@byte5, UNKNOWN=0@byte6, SEQUENCE@byte7 hi nibble, checksum@bits60-71.
	// For the test we'll skip the 12-bit header checksum (not validated by the assembler).
	hdr[0] = 0x15
	hdr[1] = 0x90
	hdr[2] = byte(tg >> 8)
	hdr[3] = byte(tg & 0xFF)
	hdr[4] = byte(nBlocks)
	hdr[5] = 1 // FORMAT=1 ("unicode")
	hdr[6] = 0
	hdr[7] = byte(seq << 4) // SEQUENCE in hi nibble
	hdr[8] = 0              // checksum lo byte (stubbed)

	// Build data blocks.
	for blockNum := 1; blockNum <= nBlocks; blockNum++ {
		var lcw [9]byte
		lcw[0] = 0x17 // LCO=23
		lcw[1] = 0x90 // MFID
		lcw[2] = byte(blockNum)
		lcw[3] = byte(seq << 4) // SEQUENCE in hi nibble

		// Extract a fixed 44-bit fragment starting at bit offset (blockNum-1)*44.
		// On the wire every data block carries a full 44 bits; if the source
		// buffer ends mid-fragment, zero-pad the tail (matches the assembler's
		// padded reassembly). Always work with exactly 44 bits so the byte
		// packing below never overruns.
		start := (blockNum - 1) * 44
		var fragment [44]uint8
		for i := 0; i < 44 && start+i < len(bufBits); i++ {
			fragment[i] = bufBits[start+i]
		}

		// Place fragment at lcBits[28:72] -> bytes 3 lo nibble..8.
		// lcBits[28:72] = 44 bits starting mid-byte3.
		// byte3 = SEQUENCE (hi nibble) + fragment[0:4] (lo nibble).
		// bytes4-8 = fragment[4:44] (40 bits = 5 bytes).
		var loNib uint8
		for i := 0; i < 4; i++ {
			loNib |= fragment[i] << (3 - i)
		}
		lcw[3] |= loNib
		fragBytes := bitsToBytes(fragment[4:]) // 40 bits -> 5 bytes
		copy(lcw[4:], fragBytes)

		blocks = append(blocks, lcw)
	}

	return hdr, blocks
}

// TestAliasAssembler_DataBlockBeforeHeader_NoPanic verifies that a Motorola data
// block (LCO 0x17) arriving BEFORE any header on a fresh/zero-value aliasAssembler
// does NOT panic on nil-map assignment when the data block's seq nibble is 0 (no
// seq mismatch to trigger the existing map re-make at line 60). Reachable when
// joining a transmission mid-stream. The fix at line 52-54 lazy-inits the map
// before any write at line 68.
func TestAliasAssembler_DataBlockBeforeHeader_NoPanic(t *testing.T) {
	// Construct a Motorola data-block LCW: LCO 0x17, MFID 0x90, blockNum 1,
	// seq 0 (hi nibble of byte3), 44-bit fragment at lcBits[28:72] (byte3 lo nibble
	// + bytes 4-8). Layout: [LCO][MFID][blockNum][seq<<4 | fragHi4bits][fragLo40bits...].
	lcw := [9]byte{
		0x17,          // LCO
		0x90,          // MFID
		0x01,          // blockNum
		0x00,          // seq=0 (hi nibble) + first 4 bits of fragment (zero)
		0, 0, 0, 0, 0, // remaining 40 bits (5 bytes, all zero)
	}

	// Feed to a fresh zero-value assembler (no header, motoBlocks=nil, motoSeq=0).
	var a aliasAssembler
	alias, tg, _, complete := a.addMotorolaBlock(lcw)

	// Must not panic. Expect incomplete (no header, no completion possible).
	if complete {
		t.Error("unexpected completion without header")
	}
	if alias != "" {
		t.Errorf("unexpected alias %q", alias)
	}
	if tg != 0 {
		t.Errorf("unexpected tg 0x%04x", tg)
	}
}

// buildMotoHeaderLCW builds a 9-byte LCO 0x15 header word.
// Layout (lcwBits): LCO@byte0 low6, MFID@byte1, TG@[16:32], blockCount@[32:40],
//
//	format@[40:48], unknown@[48:56], seq@[56:60], checksum@[60:72].
func buildMotoHeaderLCW(tg uint16, blockCount, seq int) [9]byte {
	var w [9]byte
	w[0] = 0x15
	w[1] = 0x90
	w[2] = byte(tg >> 8)
	w[3] = byte(tg)
	w[4] = byte(blockCount)
	w[5] = 0x01 // format
	w[6] = 0x00 // unknown
	w[7] = byte(seq << 4)
	return w
}

// buildMotoBlockLCW builds a 9-byte LCO 0x17 data block carrying frag (44 bits,
// MSB-first) at lcBits[28:72] for blockNum/seq.
func buildMotoBlockLCW(blockNum, seq int, frag [44]uint8) [9]byte {
	var bits [72]uint8
	// byte0 LCO 0x17:
	bits[2], bits[3], bits[4] = 1, 0, 1 // 0x17 low bits set below explicitly
	// Simpler: set bytes directly, then OR the fragment bits.
	var w [9]byte
	w[0] = 0x17
	w[1] = 0x90
	w[2] = byte(blockNum)
	w[3] = byte(seq << 4)
	// pack frag into lcBits[28:72] = bits 28..71
	full := lcwBits(w) // 72 bits with current w
	for i := 0; i < 44; i++ {
		full[28+i] = frag[i]
	}
	// repack full into w
	var out [9]byte
	for i := 0; i < 72; i++ {
		if full[i] != 0 {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

// fragsForBuffer splits a byte buffer into blockCount 44-bit fragments
// (MSB-first), zero-padding the tail. Used to synthesize a reassembly that
// MotorolaAliasDecode will accept (or reject, depending on the buffer).
func fragsForBuffer(buf []byte, blockCount int) [][44]uint8 {
	bits := make([]uint8, blockCount*44)
	for i := 0; i < len(buf) && i*8 < len(bits); i++ {
		for b := 0; b < 8 && i*8+b < len(bits); b++ {
			if buf[i]&(1<<(7-b)) != 0 {
				bits[i*8+b] = 1
			}
		}
	}
	out := make([][44]uint8, blockCount)
	for i := 0; i < blockCount; i++ {
		copy(out[i][:], bits[i*44:(i+1)*44])
	}
	return out
}

func TestAliasAssembler_CRCFailThenRecover(t *testing.T) {
	var a aliasAssembler

	// Build a VALID reassembled buffer (SUID + 1 char + CRC) we can recover to.
	suid := []byte{0, 0, 0, 0, 0x12, 0x34, 0x56}
	valid := append(append([]byte{}, suid...), 0x41, 0x00)
	crc := CRC16GSM(valid)
	valid = append(valid, byte(crc>>8), byte(crc))
	blockCount := (len(valid)*8 + 43) / 44 // # of 44-bit blocks to carry it

	// Corrupt copy: flip one byte so CRC fails.
	bad := append([]byte{}, valid...)
	bad[7] ^= 0xFF

	// Round 1: header + corrupt blocks -> no alias, NOT permanently abandoned.
	a.addMotorolaHeader(buildMotoHeaderLCW(1234, blockCount, 5))
	badFrags := fragsForBuffer(bad, blockCount)
	var got string
	for i := 1; i <= blockCount; i++ {
		alias, _, _, done := a.addMotorolaBlock(buildMotoBlockLCW(i, 5, badFrags[i-1]))
		if done {
			got = alias
		}
	}
	if got != "" {
		t.Fatalf("round 1 emitted %q, want no alias", got)
	}
	if a.motoComplete {
		t.Fatalf("motoComplete latched after CRC failure; must stay false to allow retry")
	}

	// Round 2: SAME header re-sent, then CLEAN blocks -> alias recovered.
	a.addMotorolaHeader(buildMotoHeaderLCW(1234, blockCount, 5))
	goodFrags := fragsForBuffer(valid, blockCount)
	got = ""
	for i := 1; i <= blockCount; i++ {
		alias, _, _, done := a.addMotorolaBlock(buildMotoBlockLCW(i, 5, goodFrags[i-1]))
		if done {
			got = alias
		}
	}
	if got == "" {
		t.Fatalf("round 2 did not recover the alias after a clean retransmit")
	}
}

func TestAliasAssembler_RejectsCorruptHeader(t *testing.T) {
	var a aliasAssembler
	// Latch a sane header (blockCount=2, seq=3).
	a.addMotorolaHeader(buildMotoHeaderLCW(1234, 2, 3))
	if a.motoBlockCount != 2 || a.motoSeq != 3 {
		t.Fatalf("sane header not latched: count=%d seq=%d", a.motoBlockCount, a.motoSeq)
	}
	// Inject a garbage header with blockCount=0 (out of 1..aliasMaxBlocks).
	a.addMotorolaHeader(buildMotoHeaderLCW(9999, 0, 7))
	if a.motoBlockCount != 2 || a.motoSeq != 3 {
		t.Fatalf("corrupt header (blockCount=0) clobbered valid state: count=%d seq=%d", a.motoBlockCount, a.motoSeq)
	}
	// blockCount > aliasMaxBlocks also rejected.
	a.addMotorolaHeader(buildMotoHeaderLCW(9999, aliasMaxBlocks+1, 7))
	if a.motoBlockCount != 2 {
		t.Fatalf("corrupt header (blockCount too big) clobbered valid state: count=%d", a.motoBlockCount)
	}
}

// TestAliasAssembler_FailedSetCap verifies the motoFailedSets retry cap:
// after aliasMaxFailedSets consecutive CRC-failing complete block sets
// (same header), further blocks for that header are ignored (no alias
// emitted even for a clean set). A new header resets the counter and
// re-enables decoding.
func TestAliasAssembler_FailedSetCap(t *testing.T) {
	// Build a VALID reassembled buffer (SUID + 1 char + CRC).
	suid := []byte{0, 0, 0, 0, 0x12, 0x34, 0x56}
	valid := append(append([]byte{}, suid...), 0x41, 0x00)
	crc := CRC16GSM(valid)
	valid = append(valid, byte(crc>>8), byte(crc))
	blockCount := (len(valid)*8 + 43) / 44 // # of 44-bit blocks

	// Corrupt copy: flip one byte so CRC fails.
	bad := append([]byte{}, valid...)
	bad[7] ^= 0xFF

	var a aliasAssembler
	const tg = 1234
	const seq = 5

	// Feed header once.
	a.addMotorolaHeader(buildMotoHeaderLCW(tg, blockCount, seq))

	// Feed aliasMaxFailedSets consecutive CRC-failing block sets (same seq).
	badFrags := fragsForBuffer(bad, blockCount)
	for set := 0; set < aliasMaxFailedSets; set++ {
		for i := 1; i <= blockCount; i++ {
			alias, _, _, done := a.addMotorolaBlock(buildMotoBlockLCW(i, seq, badFrags[i-1]))
			if done || alias != "" {
				t.Fatalf("set %d, block %d: unexpected emission (alias=%q done=%v)", set, i, alias, done)
			}
		}
		// After each failing set, the partial map is cleared; verify we can feed the next set.
	}

	// Now the cap is hit. Feed one more CRC-failing set: must be ignored.
	for i := 1; i <= blockCount; i++ {
		alias, _, _, done := a.addMotorolaBlock(buildMotoBlockLCW(i, seq, badFrags[i-1]))
		if done || alias != "" {
			t.Errorf("cap+1 set (still failing), block %d: spurious emission (alias=%q done=%v)", i, alias, done)
		}
	}

	// Feed a CLEAN set (still same header/seq): must ALSO be ignored (cap hit).
	goodFrags := fragsForBuffer(valid, blockCount)
	for i := 1; i <= blockCount; i++ {
		alias, _, _, done := a.addMotorolaBlock(buildMotoBlockLCW(i, seq, goodFrags[i-1]))
		if done || alias != "" {
			t.Errorf("cap+1 set (clean), block %d: spurious emission (alias=%q done=%v)", i, alias, done)
		}
	}

	// Feed a NEW header (different seq or same seq, just a fresh header call).
	// The counter must reset and a clean set must now succeed.
	a.addMotorolaHeader(buildMotoHeaderLCW(tg, blockCount, 7)) // seq=7 (new)
	goodFrags = fragsForBuffer(valid, blockCount)              // rebuild frags for seq 7
	var got string
	for i := 1; i <= blockCount; i++ {
		alias, gotTG, _, done := a.addMotorolaBlock(buildMotoBlockLCW(i, 7, goodFrags[i-1]))
		if done {
			got = alias
			if gotTG != tg {
				t.Errorf("recovered alias tg mismatch: want %d, got %d", tg, gotTG)
			}
		}
	}
	if got == "" {
		t.Fatal("new header did not reset the cap; alias recovery failed")
	}
	want, _, ok := MotorolaAliasDecode(valid)
	if !ok {
		t.Fatal("oracle MotorolaAliasDecode failed on valid buffer")
	}
	if got != want {
		t.Errorf("recovered alias mismatch: want %q, got %q", want, got)
	}
}
