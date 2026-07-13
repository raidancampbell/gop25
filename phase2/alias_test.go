package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

// TestP2Alias_Motorola builds a MAC PDU with Motorola vendor alias sub-messages
// (header op 0x91 + data blocks op 0x95), drives it through walkMACSubMessages
// + the Phase 2 assembler, and asserts the round-trip: the assembled alias ==
// p25.MotorolaAliasDecode(buf) and tg matches. Fragment offsets are documented
// in alias.go for the live gate.
func TestP2Alias_Motorola(t *testing.T) {
	const seq = 7
	const tg = 0x1234

	// Build a valid Motorola alias buffer: 7-byte SUID + encoded alias + 2-byte CRC.
	// For test simplicity, zero SUID and a minimal 2-byte alias (1 UTF-16 char 'A').
	suid := make([]byte, 7)
	aliasBytes := []byte{0x00, 0x41} // UTF-16 'A' = 0x0041
	payload := append(suid, aliasBytes...)
	crc := p25.CRC16GSM(payload)
	buf := append(payload, byte(crc>>8), byte(crc&0xFF))
	if len(buf) != 11 {
		t.Fatalf("want 11-byte buffer, got %d", len(buf))
	}

	// Phase 2 Motorola: header carries the FIRST 64-bit fragment (bytes 0-7),
	// data blocks carry 100-bit fragments. Total bits = 88 -> first 64 bits in
	// header, remaining 24 bits in one data block (padded to 100 bits with zeros).
	// Build a MAC PDU byte buffer with the sub-messages.
	macPDU := buildMotoMACPDU(t, seq, tg, buf)

	// Decode the MAC PDU to extract vendor sub-messages via walkMACSubMessages.
	// For testing, we'll construct a MACPDU directly and call walkMACSubMessages.
	pdu := &MACPDU{
		Opcode: 3, // MAC_IDLE
		Offset: 0,
		Bytes:  macPDU,
	}
	walkMACSubMessages(pdu)

	// Feed the stashed vendor sub-messages to the Phase 2 assembler.
	var asm p2AliasAssembler
	var alias string
	var gotTG uint16
	var complete bool
	for _, msg := range pdu.vendorAliasMsgs {
		alias, gotTG, _, complete = asm.feed(msg)
		if complete {
			break
		}
	}

	if !complete {
		t.Fatal("assembler never completed (expected completion after all blocks)")
	}
	if gotTG != tg {
		t.Errorf("tg: want 0x%04x, got 0x%04x", tg, gotTG)
	}

	// Oracle: p25.MotorolaAliasDecode(buf) should match the assembled alias.
	want, _, ok := p25.MotorolaAliasDecode(buf)
	if !ok {
		t.Fatalf("oracle p25.MotorolaAliasDecode failed on synthetic buffer")
	}
	if alias != want {
		t.Errorf("alias round-trip: want %q, got %q", want, alias)
	}
}

// TestP2Alias_Harris builds a MAC PDU with a Harris vendor alias sub-message
// (op 0xA8, mfid 0xA4, ASCII payload), drives it through the assembler, and
// asserts the assembled string matches p25.HarrisAliasString.
func TestP2Alias_Harris(t *testing.T) {
	// Harris alias sub-message: op 0xA8, mfid 0xA4, len=10, ASCII payload "TEST".
	// Layout: [op][mfid][len][payload...]. Payload starts at byte 3.
	payload := []byte("TEST")
	submsg := make([]byte, 3+len(payload))
	submsg[0] = 0xA8                   // op
	submsg[1] = 0xA4                   // mfid
	submsg[2] = byte(3 + len(payload)) // total length (op+mfid+len+payload)
	copy(submsg[3:], payload)

	// Build a MAC PDU with this sub-message.
	macPDU := make([]byte, 1+len(submsg))
	macPDU[0] = (3 << 5) // MAC_IDLE opcode (top 3 bits)
	copy(macPDU[1:], submsg)

	pdu := &MACPDU{
		Opcode: 3,
		Offset: 0,
		Bytes:  macPDU,
	}
	walkMACSubMessages(pdu)

	// Feed to the assembler.
	var asm p2AliasAssembler
	alias, _, _, complete := asm.feed(pdu.vendorAliasMsgs[0])

	if !complete {
		t.Fatal("Harris alias must complete on first sub-message")
	}

	// Oracle: p25.HarrisAliasString should match the assembled alias.
	want := p25.HarrisAliasString([][]byte{payload})
	if alias != want {
		t.Errorf("Harris alias: want %q, got %q", want, alias)
	}
}

// buildMotoMACPDU constructs a MAC PDU byte buffer with Motorola vendor alias
// sub-messages: header (op 0x91, carries first 64-bit fragment + tg) and data
// blocks (op 0x95, carry 100-bit fragments). This is the INVERSE of the Phase 2
// assembler's extraction and serves as the round-trip oracle for fragment offsets.
func buildMotoMACPDU(t *testing.T, seq int, tg uint16, buf []byte) []byte {
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

	totalBits := len(bufBits)
	// Header carries first 64 bits; remaining bits go to data blocks (100 bits each).
	headerFragBits := 64
	if totalBits < headerFragBits {
		headerFragBits = totalBits
	}
	remainingBits := totalBits - headerFragBits
	nDataBlocks := (remainingBits + 99) / 100 // ceiling

	// Build MAC PDU: PDU header byte (MAC_IDLE opcode) + sub-messages.
	macPDU := []byte{3 << 5} // MAC_IDLE opcode in top 3 bits

	// Motorola header sub-message: op 0x91, mfid 0x90, len, [tg 16b][seq 4b][blockCount 4b][header fragment 64b].
	// Total payload after op+mfid+len: 2 bytes (tg) + 1 byte (seq+blockCount) + 8 bytes (64-bit fragment) = 11 bytes.
	// Sub-message length = 3 (op+mfid+len) + 11 = 14 bytes.
	hdrSubmsg := make([]byte, 14)
	hdrSubmsg[0] = 0x91 // op
	hdrSubmsg[1] = 0x90 // mfid
	hdrSubmsg[2] = 14   // length
	hdrSubmsg[3] = byte(tg >> 8)
	hdrSubmsg[4] = byte(tg & 0xFF)
	hdrSubmsg[5] = byte(seq<<4) | byte(nDataBlocks&0x0F)
	// Pack first 64 bits of buf into hdrSubmsg[6:14].
	for i := 0; i < 8 && i*8 < len(bufBits); i++ {
		var b byte
		for bit := 0; bit < 8 && i*8+bit < len(bufBits); bit++ {
			b |= bufBits[i*8+bit] << (7 - bit)
		}
		hdrSubmsg[6+i] = b
	}
	macPDU = append(macPDU, hdrSubmsg...)

	// Data block sub-messages: op 0x95, mfid 0x90, len, [blockNum 8b][seq 4b][100-bit fragment].
	// Payload: 1 byte (blockNum) + 1 nibble (seq, top nibble of next byte) + 100 bits (12.5 bytes) = total 14 bytes.
	// Sub-message length = 3 + 14 = 17 bytes. But 100 bits = 12.5 bytes, so we need 13 bytes for the fragment.
	// Actually: blockNum (1B) + seq nibble in top of next byte + 100 bits starting mid-byte.
	// Let's simplify: payload is blockNum (1B) + seq (4b, top nibble) + fragment (100b = 12.5 bytes).
	// Pack into 13 bytes: first byte is blockNum, second byte is seq (top 4 bits) + first 4 bits of fragment,
	// then 12 more bytes for the remaining 96 bits of fragment.
	// Total: 1 + 13 = 14 bytes payload -> sub-message length = 3 + 14 = 17 bytes.
	for blockNum := 1; blockNum <= nDataBlocks; blockNum++ {
		dataSubmsg := make([]byte, 17)
		dataSubmsg[0] = 0x95 // op
		dataSubmsg[1] = 0x90 // mfid
		dataSubmsg[2] = 17   // length
		dataSubmsg[3] = byte(blockNum)
		dataSubmsg[4] = byte(seq << 4) // seq in top nibble

		// Extract 100-bit fragment starting at bit offset headerFragBits + (blockNum-1)*100.
		start := headerFragBits + (blockNum-1)*100
		var fragBits [100]uint8
		for i := 0; i < 100 && start+i < len(bufBits); i++ {
			fragBits[i] = bufBits[start+i]
		}

		// Pack fragment into dataSubmsg[5:18] (13 bytes).
		// First 4 bits of fragment go into lo nibble of dataSubmsg[4].
		for i := 0; i < 4; i++ {
			dataSubmsg[4] |= fragBits[i] << (3 - i)
		}
		// Remaining 96 bits -> 12 bytes starting at dataSubmsg[5].
		for i := 4; i < 100; i++ {
			byteIdx := 5 + (i-4)/8
			bitInByte := 7 - (i-4)%8
			dataSubmsg[byteIdx] |= fragBits[i] << bitInByte
		}

		macPDU = append(macPDU, dataSubmsg...)
	}

	return macPDU
}

// TestP2Alias_DataBlockBeforeHeader_NoPanic verifies that a Motorola data
// block (op 0x95) arriving BEFORE any header on a fresh/zero-value
// p2AliasAssembler does NOT panic on nil-map assignment when the data block's
// seq nibble is 0 (no seq mismatch to trigger the existing map re-make at
// line 131). Reachable when joining a transmission mid-stream or after
// ResetSlot. The fix at line 117 lazy-inits the map before any write at 151.
func TestP2Alias_DataBlockBeforeHeader_NoPanic(t *testing.T) {
	// Construct a Motorola data-block vendor sub-message: op 0x95, mfid 0x90,
	// len 17, blockNum 1, seq 0 (top nibble), 100-bit fragment (13 bytes).
	// Layout: [op][mfid][len][blockNum][seq<<4 | fragHi4bits][fragLo96bits...].
	dataBlock := vendorSubMsg{
		op:   0x95,
		mfid: 0x90,
		body: []byte{
			0x95,                               // op
			0x90,                               // mfid
			17,                                 // length
			1,                                  // blockNum
			0x00,                               // seq=0 (top nibble) + first 4 bits of fragment (zero)
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // remaining 96 bits (12 bytes, all zero)
		},
	}

	// Feed to a fresh zero-value assembler (no header, motoBlocks=nil, motoSeq=0).
	var asm p2AliasAssembler
	alias, tg, _, complete := asm.feed(dataBlock)

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

// synthP2Set returns the header + data-block sub-messages that reassemble to buf.
func synthP2Set(buf []byte, tg uint16, seq, blockCount int) []vendorSubMsg {
	bits := make([]uint8, 64+blockCount*100)
	for i := 0; i < len(buf) && i*8 < len(bits); i++ {
		for b := 0; b < 8 && i*8+b < len(bits); b++ {
			if buf[i]&(1<<(7-b)) != 0 {
				bits[i*8+b] = 1
			}
		}
	}
	// Header sub-message: op,mfid,len,tg(2),seq|blockCount,fragment(8).
	hdrFrag := packBits(bits[0:64])
	hdr := append([]byte{0x91, 0x90, 0x00, byte(tg >> 8), byte(tg), byte(seq<<4 | blockCount)}, hdrFrag...)
	msgs := []vendorSubMsg{{op: 0x91, mfid: 0x90, body: hdr}}
	for blk := 1; blk <= blockCount; blk++ {
		frag := bits[64+(blk-1)*100 : 64+blk*100]
		// body[4] = seq<<4 | first 4 frag bits; body[5:17] = next 96 bits.
		b4 := byte(seq << 4)
		for i := 0; i < 4; i++ {
			if frag[i] != 0 {
				b4 |= 1 << (3 - i)
			}
		}
		rest := packBits(frag[4:100]) // 96 bits -> 12 bytes
		body := append([]byte{0x95, 0x90, 0x00, byte(blk), b4}, rest...)
		msgs = append(msgs, vendorSubMsg{op: 0x95, mfid: 0x90, body: body})
	}
	return msgs
}

// packBits packs an MSB-first bit slice (len multiple of 8) into bytes.
func packBits(bits []uint8) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b != 0 {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

func TestP2AliasAssembler_CRCFailThenRecover(t *testing.T) {
	suid := []byte{0, 0, 0, 0, 0x12, 0x34, 0x56}
	valid := append(append([]byte{}, suid...), 0x41, 0x00)
	crc := p25.CRC16GSM(valid)
	valid = append(valid, byte(crc>>8), byte(crc))
	// 64 header bits + N*100 >= len(valid)*8; one block (164 bits) covers 11 bytes.
	blockCount := 1
	for 64+blockCount*100 < len(valid)*8 {
		blockCount++
	}

	bad := append([]byte{}, valid...)
	bad[8] ^= 0xFF

	var a p2AliasAssembler
	for _, m := range synthP2Set(bad, 1234, 5, blockCount) {
		_, _, _, done := a.feed(m)
		if done {
			t.Fatalf("emitted alias from corrupt set")
		}
	}
	if a.motoComplete {
		t.Fatalf("motoComplete latched on CRC failure; must allow retry")
	}

	var got string
	for _, m := range synthP2Set(valid, 1234, 5, blockCount) {
		alias, _, _, done := a.feed(m)
		if done {
			got = alias
		}
	}
	if got == "" {
		t.Fatalf("did not recover alias after clean retransmit")
	}
}
