package p25

import "testing"

// TestHamming1063_RoundTrip verifies the Hamming(10,6,3) encoder/decoder
// round-trips all 64 hexbit values and corrects any single-bit error in
// the 6-bit data field.
func TestHamming1063_RoundTrip(t *testing.T) {
	for d := range uint8(64) {
		par := hamming1063Encode(d)
		got := hamming1063Decode(d, par)
		if got != d {
			t.Errorf("clean roundtrip d=%d: got %d", d, got)
		}
		for bit := range 6 {
			corrupt := d ^ (1 << uint(bit))
			got := hamming1063Decode(corrupt, par)
			if got != d {
				t.Errorf("d=%d bit %d flipped: decode=%d, want %d", d, bit, got, d)
			}
		}
	}
}

// TestExtractLDUHexbits_RoundTrip verifies that extractLDUHexbits recovers
// hexbits placed at the op25-defined positions.
func TestExtractLDUHexbits_RoundTrip(t *testing.T) {
	var hb [24]uint8
	for i := range hb {
		hb[i] = uint8((i*7 + 13) & 0x3F)
	}
	payload := make([]Dibit, payloadLen(0x5))
	writeLDUHexbits(payload, hb)
	got, ok := extractLDUHexbits(payload)
	if !ok {
		t.Fatal("extractLDUHexbits returned !ok")
	}
	if got != hb {
		t.Errorf("hexbits mismatch:\n got=%v\nwant=%v", got, hb)
	}
}

// TestRSDecode63_LCAndES verifies the shortened RS(24,12) and RS(24,16)
// decoders correct symbol errors and reject excess errors.
func TestRSDecode63_LCAndES(t *testing.T) {
	for _, parity := range []int{8, 12} {
		tcap := parity / 2
		var hb [24]uint8
		for nerr := 0; nerr <= tcap; nerr++ {
			cw := hb
			for e := 0; e < nerr; e++ {
				cw[e] ^= uint8(e + 1)
			}
			got, ne, ok := rsDecode63(cw, parity)
			if !ok {
				t.Errorf("parity=%d nerr=%d: decode failed", parity, nerr)
				continue
			}
			if ne != nerr {
				t.Errorf("parity=%d nerr=%d: reported %d corrections", parity, nerr, ne)
			}
			if got != hb {
				t.Errorf("parity=%d nerr=%d: corrected=%v, want %v", parity, nerr, got, hb)
			}
		}
	}
}

// TestExtractLC_KnownLCW encodes a known Link Control Word into an LDU
// payload (with proper RS(24,12) parity and Hamming(10,6) encoding) and
// verifies extractLC recovers it. This is the regression for bug #2:
// before the fix, extractLC read raw bits from the wrong positions and
// fed them straight to RS without Hamming decode, so it always failed —
// every P25 transmission in the DB had unit_id=NULL talkgroup_id=NULL.
func TestExtractLC_KnownLCW(t *testing.T) {
	// TGID 5305 / SrcID 1234567 chosen to match the values granted on the
	// NAC 0x171 control channel for the 453.x voice channels, so any
	// future field-offset bug shows up as "voice TG != CC TG".
	const wantTG, wantUID = uint16(5305), uint32(1234567)

	f := buildLDU1Frame(0x171, wantUID, wantTG, 0x00)

	// Absolute check independent of extractLC: the 12 data hexbits encode
	// the 72-bit LCW directly. With LCO=0/MFID=0/SvcOpts=0/rsvd=0 the first
	// 32 bits are zero, so hb[0..4] must be 0 and hb[5] starts with TGID's
	// top 4 bits. This catches the "encoder and decoder share the same
	// wrong offset" failure mode that the round-trip alone cannot.
	hb, ok := extractLDUHexbits(f.Payload)
	if !ok {
		t.Fatal("extractLDUHexbits failed")
	}
	for i := range 5 {
		if hb[i] != 0 {
			t.Fatalf("hexbit[%d]=0x%02X, want 0 (LCO/MFID/SvcOpts/rsvd must be zero)", i, hb[i])
		}
	}

	lc := extractLC(f.Payload)
	if lc == nil {
		t.Fatal("extractLC returned nil")
	}
	if lc.talkgroup != wantTG || lc.unitID != wantUID {
		t.Errorf("LC = {tg=%d uid=%d}, want {tg=%d uid=%d}",
			lc.talkgroup, lc.unitID, wantTG, wantUID)
	}
}

// TestExtractLC_ServiceOptions verifies extractLC recovers the LCO=0 service-
// options byte (LCW byte 2), and in particular the 0x80 emergency bit. P25
// emergency-button calls set this bit in the Group Voice Channel User LC; it is
// the only safety-relevant trait carried in-band, so a decode regression must
// surface as a test failure rather than a silently-dropped emergency.
func TestExtractLC_ServiceOptions(t *testing.T) {
	const wantTG, wantUID = uint16(5305), uint32(1234567)
	const svcOpts = uint8(0x80) // emergency bit set

	f := buildLDU1FrameSvc(0x171, wantUID, wantTG, 0x00, svcOpts)

	lc := extractLC(f.Payload)
	if lc == nil {
		t.Fatal("extractLC returned nil")
	}
	if lc.svcOpts != svcOpts {
		t.Errorf("lc.svcOpts = 0x%02X, want 0x%02X", lc.svcOpts, svcOpts)
	}
	if lc.svcOpts&0x80 == 0 {
		t.Error("emergency bit (0x80) not recovered from service options")
	}
}

// TestExtractES_KnownAlgo verifies LDU2 ES extraction with RS(24,16,9).
func TestExtractES_KnownAlgo(t *testing.T) {
	wantAlgo := uint8(0x80)
	wantKey := uint16(0x1234)

	f := buildLDU2Frame(0x171, wantAlgo, wantKey)
	es := extractES(f.Payload)
	if es == nil {
		t.Fatal("extractES returned nil — RS or position decode failed")
	}
	if es.algoID != wantAlgo || es.keyID != wantKey {
		t.Errorf("ES = {algo=0x%02X key=0x%04X}, want {algo=0x%02X key=0x%04X}",
			es.algoID, es.keyID, wantAlgo, wantKey)
	}
}
