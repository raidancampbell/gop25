package p25

// Phase 1 talker-alias reassembler state machine. Collects Motorola header +
// sequenced data blocks (or Harris blocks 1-4) across LDU1/TDULC frames and
// emits the completed alias. References:
//   - sdrtrunk LCMotorolaTalkerAliasAssembler.java (Motorola state machine)
//   - sdrtrunk LCHarrisTalkerAliasComplete.java (Harris assembly)
// Bit layouts per docs/superpowers/plans/2026-06-29-p25-lco3-talker-alias.md.

// aliasAssembler collects Phase 1 alias LC words (one per LDU1/TDULC frame)
// and reports completion.
type aliasAssembler struct {
	// Motorola state (LCO 0x15 header + LCO 0x17 data blocks).
	motoSeq        int               // sequence nibble from header (4 bits)
	motoBlockCount int               // expected # data blocks
	motoTG         uint16            // talkgroup from header
	motoBlocks     map[int][44]uint8 // BLOCK_NUMBER (1..count) -> 44-bit fragment
	motoComplete   bool              // already emitted once?
	motoFailedSets int               // # CRC-failed reassemblies since last valid header

	// Harris state (LCO 50-53 blocks 1-4).
	harrisBlocks   [4][]byte // indexed by block position (LCO-50)
	harrisComplete bool      // already emitted once?

	// Harris Talker GPS state (LCO 42 block 1 + LCO 43 block 2). Each block
	// carries 56 payload bits (bytes 2-8); the two concatenate into the 112-bit
	// field decoded by DecodeHarrisGPS.
	harrisGPSBlocks   [2][]uint8 // indexed by block position (LCO-42)
	harrisGPSComplete bool       // already emitted once?
}

// addMotorolaHeader latches {sequence, blockCount, tg} and clears any partial
// block set. Returns (alias, tg, unit, complete); complete is false for headers.
func (a *aliasAssembler) addMotorolaHeader(lcw [9]byte) (string, uint16, uint32, bool) {
	lcBits := lcwBits(lcw)
	tg := uint16(bitsToUint32(lcBits[16:32]))
	blockCount := int(lcBits[32])<<7 | int(lcBits[33])<<6 | int(lcBits[34])<<5 | int(lcBits[35])<<4 |
		int(lcBits[36])<<3 | int(lcBits[37])<<2 | int(lcBits[38])<<1 | int(lcBits[39])
	seq := int(lcBits[56])<<3 | int(lcBits[57])<<2 | int(lcBits[58])<<1 | int(lcBits[59])

	// Sanity-gate the header: a blockCount outside 1..aliasMaxBlocks is a
	// corrupt header the LC FEC did not catch. Reject it WITHOUT disturbing any
	// valid in-progress reassembly. sdrtrunk LCMotorolaTalkerAliasHeader.java:69.
	if blockCount < 1 || blockCount > aliasMaxBlocks {
		return "", 0, 0, false
	}

	// Reset state on new (valid) header.
	a.motoSeq = seq
	a.motoBlockCount = blockCount
	a.motoTG = tg
	a.motoBlocks = make(map[int][44]uint8)
	a.motoComplete = false
	a.motoFailedSets = 0

	return "", 0, 0, false
}

// addMotorolaBlock stores the 44-bit fragment if the sequence matches the
// latched header. When all blockCount blocks are present, reassembles +
// decodes the alias and returns (alias, tg, unit, true) ONCE. Subsequent calls
// return complete=false to avoid re-emitting.
func (a *aliasAssembler) addMotorolaBlock(lcw [9]byte) (string, uint16, uint32, bool) {
	if a.motoComplete || a.motoFailedSets >= aliasMaxFailedSets {
		return "", 0, 0, false
	}

	if a.motoBlocks == nil {
		a.motoBlocks = make(map[int][44]uint8)
	}

	lcBits := lcwBits(lcw)
	blockNum := int(bitsToUint32(lcBits[16:24]))
	seq := int(lcBits[24])<<3 | int(lcBits[25])<<2 | int(lcBits[26])<<1 | int(lcBits[27])

	if seq != a.motoSeq {
		a.motoBlocks = make(map[int][44]uint8)
		return "", 0, 0, false
	}

	var frag [44]uint8
	copy(frag[:], lcBits[28:72])
	a.motoBlocks[blockNum] = frag

	if len(a.motoBlocks) < a.motoBlockCount {
		return "", 0, 0, false
	}
	for i := 1; i <= a.motoBlockCount; i++ {
		if _, ok := a.motoBlocks[i]; !ok {
			return "", 0, 0, false
		}
	}

	totalBits := a.motoBlockCount * 44
	paddedBits := ((totalBits + 7) / 8) * 8
	bufBits := make([]uint8, paddedBits)
	for i := 1; i <= a.motoBlockCount; i++ {
		frag := a.motoBlocks[i]
		copy(bufBits[(i-1)*44:], frag[:])
	}
	buf := bitsToBytes(bufBits)

	alias, unit, ok := MotorolaAliasDecode(buf)
	if !ok {
		for len(buf) > 7+2 {
			if buf[len(buf)-1] == 0 {
				buf = buf[:len(buf)-1]
				alias, unit, ok = MotorolaAliasDecode(buf)
				if ok {
					break
				}
			} else {
				break
			}
		}
	}

	if !ok {
		// CRC failed for this block set. Do NOT permanently abandon the alias:
		// Motorola retransmits aliases continuously, so a clean set may follow.
		// Clear the partial set and bump the bounded failure counter; a new
		// header resets it (addMotorolaHeader). Leave motoComplete false.
		a.motoBlocks = make(map[int][44]uint8)
		a.motoFailedSets++
		return "", 0, 0, false
	}

	a.motoComplete = true
	return alias, a.motoTG, unit, true
}

// addHarris stores the 56-bit payload (bytes 2-8) by block position (LCO-50).
// Assembles via HarrisAliasString once blocks 0 AND 1 are present, then RE-EMITS
// a progressively richer alias as later blocks (2, 3) arrive, mirroring
// sdrtrunk LCHarrisTalkerAliasComplete (which re-assembles on every block 1-4).
// Returns (alias, 0, unit, true) each time a NEW block advances the alias.
// Harris has no sequence number or talkgroup in the LC word; unit is always 0.
//
// Blocks arrive in order 1,2,3,4, so latching after only blocks 1+2 (as an
// earlier version did) truncated any alias spanning blocks 3-4. Instead we
// dedup on block position (a re-fed block does not re-emit) and latch the whole
// alias only once block 4 (pos 3, LCO 53) has been folded in.
func (a *aliasAssembler) addHarris(lcw [9]byte) (string, uint16, uint32, bool) {
	if a.harrisComplete {
		return "", 0, 0, false
	}

	lco := int(lcw[0] & 0x3F)
	pos := lco - 50
	if pos < 0 || pos >= 4 {
		// Invalid LCO for Harris alias.
		return "", 0, 0, false
	}

	// Dedup: a re-transmitted block already folded in does not re-emit. Only a
	// newly-seen block position advances (and re-emits) the alias.
	if a.harrisBlocks[pos] != nil {
		return "", 0, 0, false
	}

	// Payload = bytes 2-8 (7 ASCII chars).
	payload := make([]byte, 7)
	copy(payload, lcw[2:9])
	a.harrisBlocks[pos] = payload

	// Assemble once blocks 0 AND 1 are present (sdrtrunk LCHarrisTalkerAliasComplete:92-117).
	if a.harrisBlocks[0] == nil || a.harrisBlocks[1] == nil {
		return "", 0, 0, false
	}

	// Build slice for HarrisAliasString (it skips nil entries).
	blocks := [][]byte{a.harrisBlocks[0], a.harrisBlocks[1], a.harrisBlocks[2], a.harrisBlocks[3]}
	alias := HarrisAliasString(blocks)

	// Latch only after the final block (pos 3 = LCO 53) has been incorporated,
	// so blocks 3-4 are not dropped. Downstream last-write-wins converges to the
	// complete alias across the progressive emissions.
	if a.harrisBlocks[3] != nil {
		a.harrisComplete = true
	}
	return alias, 0, 0, true
}

// addHarrisGPSBlock stores the 56-bit payload (bytes 2-8 = LCW bits[16:72]) of a
// Harris Talker GPS block by position (LCO 42 = block 1, LCO 43 = block 2). Once
// both blocks are present it concatenates them into the 112-bit field and decodes
// it, returning (pos, true) ONCE. Subsequent calls return complete=false.
// Reference: sdrtrunk LCHarrisTalkerGPSComplete.create (block1[16:72] ++ block2[16:72]).
func (a *aliasAssembler) addHarrisGPSBlock(lco uint8, lcw [9]byte) (GPSPosition, bool) {
	if a.harrisGPSComplete {
		return GPSPosition{}, false
	}

	pos := int(lco) - 42
	if pos < 0 || pos >= 2 {
		return GPSPosition{}, false
	}

	bits := lcwBits(lcw)
	frag := make([]uint8, 56)
	copy(frag, bits[16:72])
	a.harrisGPSBlocks[pos] = frag

	if a.harrisGPSBlocks[0] == nil || a.harrisGPSBlocks[1] == nil {
		return GPSPosition{}, false
	}

	field := make([]uint8, 0, 112)
	field = append(field, a.harrisGPSBlocks[0]...)
	field = append(field, a.harrisGPSBlocks[1]...)

	pos2, ok := DecodeHarrisGPS(field)
	if !ok {
		// Corrupt field the LC FEC let through: clear the partial set so a clean
		// retransmission can reassemble. Harris repeats GPS continuously.
		a.harrisGPSBlocks = [2][]uint8{}
		return GPSPosition{}, false
	}

	a.harrisGPSComplete = true
	return pos2, true
}

// lcwBits expands a 9-byte LC word to a 72-element MSB-first bit slice.
func lcwBits(lcw [9]byte) []uint8 {
	bits := make([]uint8, 72)
	for i, b := range lcw {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<(7-bit)) != 0 {
				bits[i*8+bit] = 1
			}
		}
	}
	return bits
}
