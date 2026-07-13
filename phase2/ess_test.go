package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

// --- RS encoder for tests ---

// essRSEncode computes the 28 parity hexbits (ESS_A) for 16 data hexbits
// (ESS_B) using the RS(63,35) code over GF(2^6). The shortened codeword
// has 16 data symbols at positions 28-43 (reversed) and 28 parity symbols
// at positions 0-27 (reversed).
func essRSEncode(data [16]uint8) [28]uint8 {
	// Build generator polynomial: g(x) = ∏(x - α^i), i=1..28.
	gen := []uint8{1}
	for i := 1; i <= 28; i++ {
		root := p25.GFExp(i)
		next := make([]uint8, len(gen)+1)
		for j, c := range gen {
			next[j+1] ^= c
			next[j] ^= p25.GFMul(c, root)
		}
		gen = next
	}

	// Place data at high positions: msg[43-i] = data[i], rest = 0.
	var msg [63]uint8
	for i := 0; i < 16; i++ {
		msg[43-i] = data[i]
	}

	// Polynomial long division: remainder = msg mod g(x).
	rem := make([]uint8, 63)
	copy(rem, msg[:])
	for i := 62; i >= 28; i-- {
		c := rem[i]
		if c == 0 {
			continue
		}
		for j := 0; j <= 28; j++ {
			rem[i-28+j] ^= p25.GFMul(c, gen[j])
		}
	}

	// Extract parity from positions 0..27, reversed to ESS_A ordering.
	var parity [28]uint8
	for i := 0; i < 28; i++ {
		parity[i] = rem[27-i]
	}
	return parity
}

// packESSHexbits packs AlgID, KeyID, MI into 16 hexbits (6-bit symbols).
func packESSHexbits(algID uint8, keyID uint16, mi [9]byte) [16]uint8 {
	var hb [16]uint8
	// AlgID: 8 bits → hb[0] (top 6) + hb[1] (top 2)
	hb[0] = algID >> 2
	hb[1] = (algID&0x03)<<4 | uint8(keyID>>12)
	hb[2] = uint8((keyID >> 6) & 0x3F)
	hb[3] = uint8(keyID & 0x3F)

	// MI: 9 bytes (72 bits) → hb[4..15], 3 bytes per 4 hexbits
	j := 0
	for i := 0; i < 9; {
		hb[j+4] = mi[i] >> 2
		hb[j+5] = (mi[i]&0x03)<<4 | mi[i+1]>>4
		hb[j+6] = (mi[i+1]&0x0F)<<2 | mi[i+2]>>6
		hb[j+7] = mi[i+2] & 0x3F
		i += 3
		j += 4
	}
	return hb
}

// makeBurstWithESS_B creates a 4V burst with ESS-B hexbits placed at the
// correct burst positions (12 dibits at PayloadOffset+ESSOffset).
func makeBurstWithESS_B(slot int, hexbits [4]uint8) Burst {
	b := make4VBurst(slot)
	essStart := PayloadOffset + ESSOffset
	// Each hexbit → 3 dibits: (hb>>4)&3, (hb>>2)&3, hb&3
	for i := 0; i < 4; i++ {
		hb := hexbits[i]
		b.Dibits[essStart+i*3] = p25.Dibit((hb >> 4) & 0x03)
		b.Dibits[essStart+i*3+1] = p25.Dibit((hb >> 2) & 0x03)
		b.Dibits[essStart+i*3+2] = p25.Dibit(hb & 0x03)
	}
	return b
}

// makeBurstWithESS_A creates a 2V burst with ESS-A hexbits placed at the
// correct burst positions (85 dibits starting at PayloadOffset+ESSOffset,
// with a 1-dibit skip after hexbit 15).
func makeBurstWithESS_A(slot int, hexbits [28]uint8) Burst {
	b := make2VBurst(slot)
	essStart := PayloadOffset + ESSOffset
	j := 0
	for i := 0; i < 28; i++ {
		hb := hexbits[i]
		b.Dibits[essStart+j] = p25.Dibit((hb >> 4) & 0x03)
		b.Dibits[essStart+j+1] = p25.Dibit((hb >> 2) & 0x03)
		b.Dibits[essStart+j+2] = p25.Dibit(hb & 0x03)
		if i == 15 {
			j += 4 // skip DUID dibit
		} else {
			j += 3
		}
	}
	return b
}

func TestESSState_NewDefaults(t *testing.T) {
	e := NewESSState()
	if e.AlgID != 0x80 {
		t.Errorf("default AlgID = 0x%02X, want 0x80", e.AlgID)
	}
	if e.Valid {
		t.Error("new ESSState should not be Valid")
	}
	if e.Encrypted() {
		t.Error("new ESSState should not be Encrypted")
	}
}

func TestESSState_Reset(t *testing.T) {
	e := NewESSState()
	e.AlgID = 0xAA
	e.KeyID = 0x1234
	e.Valid = true
	e.Reset()
	if e.AlgID != 0x80 {
		t.Errorf("after reset: AlgID = 0x%02X, want 0x80", e.AlgID)
	}
	if e.Valid {
		t.Error("after reset: should not be Valid")
	}
}

func TestESSState_Extract4V_Hexbits(t *testing.T) {
	e := NewESSState()
	// Feed 4 × 4V bursts with known hexbits.
	for burstIdx := 0; burstIdx < 4; burstIdx++ {
		hb := [4]uint8{
			uint8(burstIdx*4 + 1),
			uint8(burstIdx*4 + 2),
			uint8(burstIdx*4 + 3),
			uint8(burstIdx*4 + 4),
		}
		b := makeBurstWithESS_B(0, hb)
		e.Feed(Burst4V, b.Dibits)
	}
	// Verify ESS_B accumulated correctly.
	for i := 0; i < 16; i++ {
		want := uint8(i + 1)
		if e.essB[i] != want {
			t.Errorf("essB[%d] = %d, want %d", i, e.essB[i], want)
		}
	}
}

func TestESSState_Extract2V_Hexbits(t *testing.T) {
	e := NewESSState()
	// Construct a 2V burst with known hexbits.
	var hb [28]uint8
	for i := range hb {
		hb[i] = uint8(i+1) & 0x3F // 6-bit values
	}
	b := makeBurstWithESS_A(0, hb)
	// Force burstID to 4 by calling Feed with Burst2V
	e.burstID = 3 // so next 2V sets it to 4
	e.Feed(Burst2V, b.Dibits)

	for i := 0; i < 28; i++ {
		if e.essA[i] != hb[i] {
			t.Errorf("essA[%d] = 0x%02X, want 0x%02X", i, e.essA[i], hb[i])
		}
	}
}

func TestESSState_DecodeAllZeros(t *testing.T) {
	// All-zeros is a valid RS codeword. AlgID=0, KeyID=0, MI=all zeros.
	e := NewESSState()

	// Feed 4 × 4V with zero hexbits
	for i := 0; i < 4; i++ {
		b := make4VBurst(0)
		e.Feed(Burst4V, b.Dibits)
	}
	// Feed 1 × 2V with zero hexbits
	b := make2VBurst(0)
	e.Feed(Burst2V, b.Dibits)

	if !e.Valid {
		t.Fatal("all-zeros codeword should decode successfully")
	}
	if e.AlgID != 0 {
		t.Errorf("AlgID = 0x%02X, want 0", e.AlgID)
	}
	if e.KeyID != 0 {
		t.Errorf("KeyID = 0x%04X, want 0", e.KeyID)
	}
	for i, b := range e.MI {
		if b != 0 {
			t.Errorf("MI[%d] = 0x%02X, want 0", i, b)
		}
	}
	if e.Encrypted() {
		t.Error("AlgID=0 should not be considered encrypted")
	}
}

func TestESSState_DecodeClear(t *testing.T) {
	// AlgID=0x80 ("clear") is the standard "no encryption" marker.
	algID := uint8(0x80)
	keyID := uint16(0)
	mi := [9]byte{}

	data := packESSHexbits(algID, keyID, mi)
	parity := essRSEncode(data)

	e := NewESSState()
	for i := 0; i < 4; i++ {
		hb := [4]uint8{data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]}
		b := makeBurstWithESS_B(0, hb)
		e.Feed(Burst4V, b.Dibits)
	}
	b := makeBurstWithESS_A(0, parity)
	e.Feed(Burst2V, b.Dibits)

	if !e.Valid {
		t.Fatal("ESS decode failed for AlgID=0x80")
	}
	if e.AlgID != 0x80 {
		t.Errorf("AlgID = 0x%02X, want 0x80", e.AlgID)
	}
	if e.Encrypted() {
		t.Error("AlgID=0x80 should not be considered encrypted")
	}
}

func TestESSState_DecodeEncrypted(t *testing.T) {
	// ADP: AlgID=0xAA, KeyID=0x0001, MI=known pattern.
	algID := uint8(0xAA)
	keyID := uint16(0x0001)
	mi := [9]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x42}

	data := packESSHexbits(algID, keyID, mi)
	parity := essRSEncode(data)

	e := NewESSState()
	for i := 0; i < 4; i++ {
		hb := [4]uint8{data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]}
		b := makeBurstWithESS_B(0, hb)
		e.Feed(Burst4V, b.Dibits)
	}
	b := makeBurstWithESS_A(0, parity)
	e.Feed(Burst2V, b.Dibits)

	if !e.Valid {
		t.Fatal("ESS decode failed for encrypted call")
	}
	if e.AlgID != algID {
		t.Errorf("AlgID = 0x%02X, want 0x%02X", e.AlgID, algID)
	}
	if e.KeyID != keyID {
		t.Errorf("KeyID = 0x%04X, want 0x%04X", e.KeyID, keyID)
	}
	for i, b := range e.MI {
		if b != mi[i] {
			t.Errorf("MI[%d] = 0x%02X, want 0x%02X", i, b, mi[i])
		}
	}
	if !e.Encrypted() {
		t.Error("AlgID=0xAA should be considered encrypted")
	}
}

func TestESSState_DecodeWithErrors(t *testing.T) {
	// RS(44,16) can correct up to 14 symbol errors. Introduce a few.
	algID := uint8(0xAA)
	keyID := uint16(0x5678)
	mi := [9]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7}

	data := packESSHexbits(algID, keyID, mi)
	parity := essRSEncode(data)

	// Corrupt 3 parity symbols
	parity[0] ^= 0x15
	parity[7] ^= 0x2A
	parity[20] ^= 0x3F

	e := NewESSState()
	for i := 0; i < 4; i++ {
		hb := [4]uint8{data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]}
		b := makeBurstWithESS_B(0, hb)
		e.Feed(Burst4V, b.Dibits)
	}
	b := makeBurstWithESS_A(0, parity)
	e.Feed(Burst2V, b.Dibits)

	if !e.Valid {
		t.Fatal("ESS decode should succeed with 3 symbol errors (t=14)")
	}
	if e.AlgID != algID {
		t.Errorf("AlgID = 0x%02X, want 0x%02X", e.AlgID, algID)
	}
	if e.KeyID != keyID {
		t.Errorf("KeyID = 0x%04X, want 0x%04X", e.KeyID, keyID)
	}
}

func TestESSState_NonVoiceBurstIgnored(t *testing.T) {
	e := NewESSState()
	// Feeding a SACCH burst should be a no-op.
	var dibits [BurstDibits]p25.Dibit
	e.Feed(BurstSACCH, dibits)
	if e.burstID != -1 {
		t.Errorf("burstID = %d after SACCH feed, want -1", e.burstID)
	}
}

func TestESSState_BurstIDCycling(t *testing.T) {
	e := NewESSState()
	var dibits [BurstDibits]p25.Dibit

	// 4 × 4V should cycle burstID 0→1→2→3
	for i := 0; i < 4; i++ {
		e.Feed(Burst4V, dibits)
		if e.burstID != i {
			t.Errorf("after 4V #%d: burstID = %d, want %d", i, e.burstID, i)
		}
	}

	// 2V should set burstID to 4
	e.Feed(Burst2V, dibits)
	if e.burstID != 4 {
		t.Errorf("after 2V: burstID = %d, want 4", e.burstID)
	}

	// Next 4V should wrap to 0
	e.Feed(Burst4V, dibits)
	if e.burstID != 0 {
		t.Errorf("after wrap 4V: burstID = %d, want 0", e.burstID)
	}
}

func TestPackESSHexbits_RoundTrip(t *testing.T) {
	// Verify packESSHexbits → decode() produces the original values.
	algID := uint8(0xAA)
	keyID := uint16(0xBCDE)
	mi := [9]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

	data := packESSHexbits(algID, keyID, mi)

	// Verify all hexbits are 6-bit (0-63).
	for i, h := range data {
		if h > 63 {
			t.Errorf("hexbit[%d] = %d > 63", i, h)
		}
	}

	// Manually unpack to verify round-trip.
	gotAlg := data[0]<<2 | data[1]>>4
	gotKey := uint16(data[1]&0x0F)<<12 | uint16(data[2])<<6 | uint16(data[3])
	if gotAlg != algID {
		t.Errorf("AlgID round-trip: got 0x%02X, want 0x%02X", gotAlg, algID)
	}
	if gotKey != keyID {
		t.Errorf("KeyID round-trip: got 0x%04X, want 0x%04X", gotKey, keyID)
	}

	var gotMI [9]byte
	j := 0
	for i := 0; i < 9; {
		gotMI[i] = data[j+4]<<2 | data[j+5]>>4
		i++
		gotMI[i] = (data[j+5]&0x0F)<<4 | data[j+6]>>2
		i++
		gotMI[i] = (data[j+6]&0x03)<<6 | data[j+7]
		i++
		j += 4
	}
	if gotMI != mi {
		t.Errorf("MI round-trip: got %X, want %X", gotMI, mi)
	}
}
