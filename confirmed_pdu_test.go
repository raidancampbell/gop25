package p25

import (
	"math/rand"
	"testing"
)

// synthConfirmedPDU builds the status-bearing dibit payload for a Confirmed
// PACKET_DATA PDU: a 1/2-rate header block followed by len(blockPayloads)
// confirmed 3/4-rate data blocks. Each data block carries DBSN=index, a valid
// CRC-9, and the supplied 16-octet payload. The header's Confirmed bit and
// BlocksToFollow field are forced to match.
func synthConfirmedPDU(header [12]byte, blockPayloads [][16]byte) []Dibit {
	header[0] |= 0x40 // Confirmed
	header[6] = (header[6] &^ 0x7f) | (byte(len(blockPayloads)) & 0x7f)
	hbits := bytesToBlockBits(header)
	appendTSBKCRC(hbits)

	enc := append([]uint8(nil), trellisEncode(hbits)...)
	for idx, payload := range blockPayloads {
		block := make([]uint8, trellis34DataLen)
		dbsn := uint8(idx) // DBSN at bits [0:7], MSB-first
		for k := 0; k < 7; k++ {
			block[k] = (dbsn >> uint(6-k)) & 1
		}
		for b := 0; b < 16; b++ { // 16-octet payload at bits [16:144]
			for j := 0; j < 8; j++ {
				block[16+b*8+j] = (payload[b] >> uint(7-j)) & 1
			}
		}
		embedCRC9(block) // CRC-9 into [7:16]
		enc = append(enc, trellis34Encode(block)...)
	}
	return buildPayloadWithStatus(enc)
}

// TestParsePDU_ConfirmedPacketData is the end-to-end synthesis round-trip for
// the confirmed-data block layer: 3/4-rate trellis + per-block CRC-9 + 16-octet
// reassembly + packet CRC-32, then SN-DATA parse. If this passes, the confirmed
// decode path is internally consistent (standard conformance is gated
// separately against a real-world corpus via per-block CRC-9).
func TestParsePDU_ConfirmedPacketData(t *testing.T) {
	// Reassembled 32-octet payload across two 16-octet confirmed blocks, laid
	// out exactly as observed on-air ([SN-DATA][user][pad][CRC-32], CRC last):
	//   [0:2]   SN-DATA header (PDUType=4, NSAPI=5 => 0x45; compression=0x00)
	//   [2:23]  user datagram (21 bytes)
	//   [23:28] pad octets (PadOctets = 5)
	//   [28:32] packet CRC-32 over [0:28] (covers SN-DATA + user + pad)
	const pad = 5
	var pl [32]byte
	pl[0] = 0x45
	pl[1] = 0x00
	for i := 2; i < 23; i++ {
		pl[i] = byte(0xA0 + i)
	}
	for i := 23; i < 28; i++ {
		pl[i] = 0xAA // pad fill
	}
	c := crc32P25(pl[:], 28*8)
	pl[28], pl[29], pl[30], pl[31] = byte(c>>24), byte(c>>16), byte(c>>8), byte(c)

	// header[0]=0x16 (PACKET_DATA), header[7]=pad, header[9]=0x02 (DataHeaderOffset=2).
	header := [12]byte{0x16, 0x00, 0x00, 0x01, 0x81, 0x15, 0x00, pad, 0x00, 0x02, 0, 0}
	var b0, b1 [16]byte
	copy(b0[:], pl[0:16])
	copy(b1[:], pl[16:32])

	pdu := parsePDU(synthConfirmedPDU(header, [][16]byte{b0, b1}))
	if pdu == nil || !pdu.HeaderCRCOK {
		t.Fatalf("header CRC failed: %+v", pdu)
	}
	if !pdu.Confirmed {
		t.Fatal("Confirmed = false, want true")
	}
	if pdu.Format != 0x16 || pdu.BlocksToFollow != 2 {
		t.Fatalf("Format=0x%02x blks=%d, want 0x16 / 2", pdu.Format, pdu.BlocksToFollow)
	}
	if len(pdu.Payload) != 32 {
		t.Fatalf("len(Payload)=%d, want 32 (16*2)", len(pdu.Payload))
	}
	for i := range pl {
		if pdu.Payload[i] != pl[i] {
			t.Fatalf("Payload[%d]=0x%02x want 0x%02x", i, pdu.Payload[i], pl[i])
		}
	}
	if pdu.ConfirmedCRC9OK != 2 {
		t.Errorf("ConfirmedCRC9OK=%d, want 2", pdu.ConfirmedCRC9OK)
	}
	if !pdu.PayloadCRCOK {
		t.Error("PayloadCRCOK=false, want true (confirmed packet CRC-32)")
	}

	sn := parseSNDCP(pdu)
	if sn == nil {
		t.Fatal("parseSNDCP returned nil for confirmed packet data")
	}
	if sn.PDUType != 4 || sn.NSAPI != 5 {
		t.Errorf("PDUType=%d NSAPI=%d, want 4/5", sn.PDUType, sn.NSAPI)
	}
	// User payload excludes the SN-DATA header, the pad octets and the CRC-32.
	if len(sn.UserPayload) != 21 {
		t.Fatalf("len(UserPayload)=%d, want 21 (payload[2:23], pad-excluded)", len(sn.UserPayload))
	}
	for i := 0; i < 21; i++ {
		if sn.UserPayload[i] != pl[2+i] {
			t.Errorf("UserPayload[%d]=0x%02x want 0x%02x", i, sn.UserPayload[i], pl[2+i])
		}
	}
}

// buildConfirmedPDUDibits is the test vehicle for the soft path: it returns
// the dibit-level confirmed PDU (header + N 3/4-rate blocks) plus the parsed
// hard-path expectation, so callers can perturb the dibits + soft and compare
// the soft decode against ground truth.
func buildConfirmedPDUDibits(t *testing.T) ([]Dibit, *PDUData) {
	t.Helper()
	const pad = 5
	var pl [32]byte
	pl[0] = 0x45
	pl[1] = 0x00
	for i := 2; i < 23; i++ {
		pl[i] = byte(0xA0 + i)
	}
	for i := 23; i < 28; i++ {
		pl[i] = 0xAA
	}
	c := crc32P25(pl[:], 28*8)
	pl[28], pl[29], pl[30], pl[31] = byte(c>>24), byte(c>>16), byte(c>>8), byte(c)
	header := [12]byte{0x16, 0x00, 0x00, 0x01, 0x81, 0x15, 0x00, pad, 0x00, 0x02, 0, 0}
	var b0, b1 [16]byte
	copy(b0[:], pl[0:16])
	copy(b1[:], pl[16:32])
	dibits := synthConfirmedPDU(header, [][16]byte{b0, b1})
	want := parsePDU(append([]Dibit(nil), dibits...))
	if want == nil || !want.HeaderCRCOK || !want.PayloadCRCOK {
		t.Fatalf("seed PDU did not parse cleanly under hard decode: %+v", want)
	}
	return dibits, want
}

// TestParsePDU_SoftRecoversNoisyConfirmedBlock proves the end-to-end win the
// plan targets: noise that breaks one or more confirmed-data blocks under
// hard-decision still decodes cleanly when soft information is supplied to
// parsePDUWithSoft. Both paths receive the same noisy input; only the
// per-block decoder differs.
func TestParsePDU_SoftRecoversNoisyConfirmedBlock(t *testing.T) {
	payload, want := buildConfirmedPDUDibits(t)

	// Find a noise seed that breaks the hard PayloadCRCOK while leaving the
	// header decodable. With sigma in the regime where the trellis34 noise
	// test already showed soft beats hard, this lands on the first or second
	// try; iterate up to a handful of seeds to keep the test deterministic
	// even as Go's RNG implementation evolves.
	var hard, softPDU *PDUData
	const sigma = 0.55
	var seed int64
	for seed = 1; seed < 32; seed++ {
		rng := rand.New(rand.NewSource(seed))
		soft := make([]float32, len(payload))
		noisy := make([]Dibit, len(payload))
		for i, d := range payload {
			x := c4fmLevels[d] + rng.NormFloat64()*sigma
			soft[i] = float32(x)
			noisy[i] = Dibit(nearestDibit(x))
		}
		hard = parsePDUWithSoft(noisy, nil)
		softPDU = parsePDUWithSoft(noisy, soft)
		if hard != nil && hard.HeaderCRCOK && !hard.PayloadCRCOK &&
			softPDU != nil && softPDU.PayloadCRCOK {
			break
		}
	}
	if seed == 32 {
		t.Fatalf("could not find a seed where hard fails and soft passes within 32 tries")
	}
	t.Logf("seed=%d sigma=%.2f hard.PayloadCRCOK=%v soft.PayloadCRCOK=%v",
		seed, sigma, hard.PayloadCRCOK, softPDU.PayloadCRCOK)

	if !softPDU.HeaderCRCOK {
		t.Fatalf("soft PDU header CRC failed; want header recovered")
	}
	if !softPDU.PayloadCRCOK {
		t.Fatalf("soft PDU payload CRC failed; want soft to recover the datagram")
	}
	if softPDU.LLID != want.LLID {
		t.Fatalf("soft LLID 0x%06x != want 0x%06x", softPDU.LLID, want.LLID)
	}
}

// TestParsePDU_ConfirmedRejectsCorruptBlock confirms that corrupting a confirmed
// data block beyond the Viterbi's correction capacity fails its CRC-9 (so
// ConfirmedCRC9OK drops) without panicking.
func TestParsePDU_ConfirmedRejectsCorruptBlock(t *testing.T) {
	var pl [16]byte
	pl[0] = 0x45
	for i := 1; i < 16; i++ {
		pl[i] = byte(i * 7)
	}
	header := [12]byte{0x16, 0x00, 0x00, 0x02, 0x22, 0x22, 0x00, 0x00, 0x00, 0x02, 0, 0}
	var b0 [16]byte
	copy(b0[:], pl[:])
	dibits := synthConfirmedPDU(header, [][16]byte{b0})

	// Corrupt many dibits near the end (within the single data block, well past
	// the 196-bit header) so it fails CRC-9 while the header still decodes.
	for i := len(dibits) - 45; i < len(dibits)-10; i++ {
		dibits[i] ^= 0x3
	}
	pdu := parsePDU(dibits)
	if pdu == nil || !pdu.HeaderCRCOK {
		t.Fatalf("header should still decode: %+v", pdu)
	}
	if pdu.ConfirmedCRC9OK != 0 {
		t.Errorf("ConfirmedCRC9OK=%d, want 0 for a heavily corrupted block", pdu.ConfirmedCRC9OK)
	}
}
