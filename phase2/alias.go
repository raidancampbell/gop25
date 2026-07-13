package phase2

import "github.com/raidancampbell/gop25"

// Phase 2 talker-alias reassembler state machine. Collects Motorola vendor
// sub-messages (header op 0x91, data blocks op 0x95) and Harris sub-messages
// (op 0xA8, mfid 0xA4) from MAC_IDLE/MAC_ACTIVE PDUs and emits the completed
// alias via the shared p25 codec. References:
//   - sdrtrunk MotorolaTalkerAliasComplete.java (Motorola reassembly)
//   - sdrtrunk LCHarrisTalkerAliasComplete.java (Harris assembly)
// Fragment offsets (for live gate verification):
//   - Motorola header (op 0x91): TG@bytes[3:5], seq@byte5 hi nibble,
//     blockCount@byte5 lo nibble, first 64-bit fragment@bytes[6:14].
//   - Motorola data block (op 0x95): blockNum@byte3, seq@byte4 hi nibble,
//     100-bit fragment starting at byte4 lo nibble (4 bits) + bytes[5:17] (96 bits).
//   - Harris (op 0xA8, mfid 0xA4): ASCII payload@bytes[3:len].
//
// Phase 2 DIFFERENCE from Phase 1: the Motorola HEADER carries the FIRST 64-bit
// fragment (Phase 1 headers carry NO fragment). Data blocks carry 100-bit fragments
// (Phase 1: 44-bit). Reassembled buffer layout remains shared: [SUID 7B][alias][CRC 2B].

// p2AliasMaxFailedSets bounds the retry count: after 4 CRC failures on the same
// seq/tg/blockCount, stop accepting data blocks (mirrors the Phase 1 threshold).
const p2AliasMaxFailedSets = 4

// p2AliasAssembler collects Phase 2 alias sub-messages and reports completion.
type p2AliasAssembler struct {
	// Motorola state (vendor op 0x91 header + op 0x95 data blocks).
	motoSeq        int             // sequence nibble from header (4 bits)
	motoBlockCount int             // expected # data blocks (from header)
	motoTG         uint16          // talkgroup from header
	motoBlocks     map[int][]uint8 // blockNum (1..count) -> 100-bit fragment
	motoHeaderFrag []uint8         // first 64-bit fragment from header
	motoComplete   bool            // already emitted once?
	motoFailedSets int             // count of CRC failures (bounded retry)

	// Harris state (vendor op 0xA8, mfid 0xA4 ASCII payload).
	harrisPayload  []byte // single ASCII payload (Harris Phase 2 is one sub-message)
	harrisComplete bool   // already emitted once?
}

// feed processes one vendor alias sub-message (from MACPDU.vendorAliasMsgs) and
// returns (alias, tg, unit, complete) when the alias is fully assembled. Returns
// complete=false for partial progress or already-emitted aliases (emit-once guard).
func (a *p2AliasAssembler) feed(msg vendorSubMsg) (string, uint16, uint32, bool) {
	switch msg.op {
	case 0x91: // Motorola header
		return a.addMotorolaHeader(msg)
	case 0x95: // Motorola data block
		return a.addMotorolaBlock(msg)
	case 0xA8: // Vendor sub-message (check mfid to distinguish Harris vs Moto ACK)
		if msg.mfid == 0xA4 {
			return a.addHarris(msg)
		}
		// Moto ACK (mfid 0x90) is not an alias message; ignore.
		return "", 0, 0, false
	default:
		return "", 0, 0, false
	}
}

// addMotorolaHeader latches {seq, blockCount, tg, first 64-bit fragment} from the
// header sub-message (op 0x91, mfid 0x90) and clears any partial block set. Returns
// (alias, tg, unit, complete); complete is false for headers. Layout per sdrtrunk
// MotorolaTalkerAliasComplete.java and the Phase 2 multiplexed vendor sub-message
// framing (deduced from Phase 1 + standard Phase 2 sub-message structure).
func (a *p2AliasAssembler) addMotorolaHeader(msg vendorSubMsg) (string, uint16, uint32, bool) {
	body := msg.body
	if len(body) < 14 { // minimum: op+mfid+len+tg(2)+seq_blockCount(1)+fragment(8)
		return "", 0, 0, false
	}

	// Extract fields from the header sub-message body:
	//   body[0] = op (0x91)
	//   body[1] = mfid (0x90)
	//   body[2] = length
	//   body[3:5] = talkgroup (16 bits)
	//   body[5] = seq (hi nibble) | blockCount (lo nibble)
	//   body[6:14] = first 64-bit fragment (8 bytes)
	tg := uint16(body[3])<<8 | uint16(body[4])
	seq := int(body[5] >> 4)
	blockCount := int(body[5] & 0x0F)

	// Gate invalid blockCount. The 4-bit nibble is already bounded 0..15; reject
	// only blockCount < 1 (no separate max-blocks gate needed in Phase 2). Do not
	// disturb in-progress state on reject.
	if blockCount < 1 {
		return "", 0, 0, false
	}

	// Extract the 64-bit header fragment (bytes 6-13, or up to end if shorter).
	headerFragBytes := body[6:]
	if len(headerFragBytes) > 8 {
		headerFragBytes = headerFragBytes[:8]
	}
	headerFrag := make([]uint8, 64)
	for i, b := range headerFragBytes {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<(7-bit)) != 0 {
				headerFrag[i*8+bit] = 1
			}
		}
	}

	// Reset state on new header.
	a.motoSeq = seq
	a.motoBlockCount = blockCount
	a.motoTG = tg
	a.motoHeaderFrag = headerFrag
	a.motoBlocks = make(map[int][]uint8)
	a.motoComplete = false
	a.motoFailedSets = 0

	return "", 0, 0, false
}

// addMotorolaBlock stores the 100-bit fragment from a data-block sub-message
// (op 0x95, mfid 0x90) if the sequence matches the latched header. When all
// blockCount blocks are present, reassembles + decodes the alias and returns
// (alias, tg, unit, true) ONCE. Subsequent calls return complete=false to avoid re-emitting.
func (a *p2AliasAssembler) addMotorolaBlock(msg vendorSubMsg) (string, uint16, uint32, bool) {
	if a.motoComplete || a.motoFailedSets >= p2AliasMaxFailedSets {
		return "", 0, 0, false
	}

	body := msg.body
	if len(body) < 17 { // minimum: op+mfid+len+blockNum(1)+seq_frag(13)
		return "", 0, 0, false
	}

	if a.motoBlocks == nil {
		a.motoBlocks = make(map[int][]uint8)
	}

	// Extract fields from the data-block sub-message body:
	//   body[0] = op (0x95)
	//   body[1] = mfid (0x90)
	//   body[2] = length
	//   body[3] = blockNum (1..blockCount)
	//   body[4] = seq (hi nibble) | first 4 bits of fragment (lo nibble)
	//   body[5:17] = remaining 96 bits of fragment (12 bytes)
	blockNum := int(body[3])
	seq := int(body[4] >> 4)

	// Ignore if sequence mismatch (mirrors Phase 1 seq-mismatch rejection).
	if seq != a.motoSeq {
		// Reset on sequence mismatch.
		a.motoBlocks = make(map[int][]uint8)
		return "", 0, 0, false
	}

	// Extract the 100-bit fragment: 4 bits from body[4] lo nibble + 96 bits from body[5:17].
	frag := make([]uint8, 100)
	for i := 0; i < 4; i++ {
		if body[4]&(1<<(3-i)) != 0 {
			frag[i] = 1
		}
	}
	for i := 0; i < 96 && 5+i/8 < len(body); i++ {
		byteIdx := 5 + i/8
		bitInByte := 7 - i%8
		if body[byteIdx]&(1<<bitInByte) != 0 {
			frag[4+i] = 1
		}
	}

	a.motoBlocks[blockNum] = frag

	// Check if we have all blocks (1..blockCount).
	if len(a.motoBlocks) < a.motoBlockCount {
		return "", 0, 0, false
	}
	for i := 1; i <= a.motoBlockCount; i++ {
		if _, ok := a.motoBlocks[i]; !ok {
			return "", 0, 0, false
		}
	}

	// Reassemble: concatenate header fragment (64 bits) + data-block fragments
	// (100 bits each, ordered by blockNum) MSB-first. Pad the bit buffer up to a
	// whole number of bytes (mirrors Phase 1 pad-to-byte logic).
	totalBits := 64 + a.motoBlockCount*100
	paddedBits := ((totalBits + 7) / 8) * 8
	bufBits := make([]uint8, paddedBits)
	copy(bufBits[0:64], a.motoHeaderFrag)
	for i := 1; i <= a.motoBlockCount; i++ {
		frag := a.motoBlocks[i]
		copy(bufBits[64+(i-1)*100:], frag)
	}

	// Pack to bytes.
	buf := bitsToBytes(bufBits)

	// Attempt p25.MotorolaAliasDecode. If CRC fails, trim trailing zero bytes and
	// retry (mirrors Phase 1 trim-retry logic, matching sdrtrunk trimTalkerAliasLength).
	alias, unit, ok := p25.MotorolaAliasDecode(buf)
	if !ok {
		// Retry with trimmed trailing zeros (one byte at a time).
		for len(buf) > 7+2 { // minimum: 7-byte SUID + 2-byte CRC
			if buf[len(buf)-1] == 0 {
				buf = buf[:len(buf)-1]
				alias, unit, ok = p25.MotorolaAliasDecode(buf)
				if ok {
					break
				}
			} else {
				break
			}
		}
	}

	if !ok {
		// Do NOT permanently abandon: a clean retransmit may follow. Clear the
		// partial set and bump the bounded failure counter (a new header resets
		// it). Mirrors the Phase 1 assembler.
		a.motoBlocks = make(map[int][]uint8)
		a.motoFailedSets++
		return "", 0, 0, false
	}
	a.motoComplete = true
	return alias, a.motoTG, unit, true
}

// addHarris decodes a Harris alias sub-message (op 0xA8, mfid 0xA4) whose ASCII
// payload starts at body[3]. Returns (alias, 0, 0, true) on completion. Phase 2
// Harris aliases are single sub-messages (no multi-block assembly), unlike Phase 1.
func (a *p2AliasAssembler) addHarris(msg vendorSubMsg) (string, uint16, uint32, bool) {
	if a.harrisComplete {
		return "", 0, 0, false
	}

	body := msg.body
	if len(body) < 4 { // minimum: op+mfid+len+at least 1 payload byte
		return "", 0, 0, false
	}

	// Payload starts at body[3] (after op, mfid, len).
	// The length field at body[2] is the total sub-message length (including op+mfid+len).
	msgLen := int(body[2] & 0x3F)
	if msgLen > len(body) {
		msgLen = len(body)
	}
	payload := body[3:msgLen]

	// Pass the payload to p25.HarrisAliasString (it trims trailing pad).
	alias := p25.HarrisAliasString([][]byte{payload})

	a.harrisComplete = true
	return alias, 0, 0, true
}

// bitsToBytes packs a bit-per-byte slice (MSB first) into bytes.
// The slice length must be a multiple of 8.
func bitsToBytes(bits []uint8) []byte {
	out := make([]byte, len(bits)/8)
	for i, b := range bits {
		out[i/8] |= b << uint(7-i%8)
	}
	return out
}

// bytesToBits expands a byte slice into an MSB-first bit slice.
func bytesToBits(b []byte) []uint8 {
	out := make([]uint8, len(b)*8)
	for i, by := range b {
		for j := 0; j < 8; j++ {
			out[i*8+j] = (by >> uint(7-j)) & 1
		}
	}
	return out
}
