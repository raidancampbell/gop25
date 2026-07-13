package phase2

import (
	"math/bits"
	"testing"

	"github.com/raidancampbell/gop25"
)

func TestISCH_TableSize(t *testing.T) {
	// 128 location codewords + 1 S-ISCH.
	if len(ischCodewords) != 129 {
		t.Errorf("expected 129 ISCH codewords, got %d", len(ischCodewords))
	}
}

func TestISCH_ExactMatch(t *testing.T) {
	for cw, want := range ischCodewords {
		dibits := cwToDibits(cw)
		info := DecodeISCH(dibits)
		if want == -2 {
			if !info.Valid || !info.IsSISCH {
				t.Errorf("cw=%010x: expected valid S-ISCH, got %+v", cw, info)
			}
			continue
		}
		// Position is loc*4+chn (op25), not want%12. Positions >=12 are not
		// real I-ISCH and decode as invalid (Location -1).
		loc := (int(want) >> 3) & 3
		chn := (int(want) >> 5) & 3
		pos := loc*4 + chn
		if pos >= SuperframeBursts {
			if info.Valid {
				t.Errorf("cw=%010x: want invalid for pos=%d, got loc=%d valid", cw, pos, info.Location)
			}
			continue
		}
		if !info.Valid {
			t.Errorf("cw=%010x: expected valid decode for pos=%d", cw, pos)
			continue
		}
		if info.Location != pos {
			t.Errorf("cw=%010x: location=%d want %d", cw, info.Location, pos)
		}
	}
}

func TestISCH_CorrectsUpTo7BitErrors(t *testing.T) {
	// Pick the codeword for location 0 and flip 7 bits.
	const target = 0x184229d461
	var corrupted uint64 = target
	flipMask := uint64(0b1111111) // 7 LSBs
	corrupted ^= flipMask
	if bits.OnesCount64(corrupted^target) != 7 {
		t.Fatalf("test setup: expected 7-bit flip")
	}
	dibits := cwToDibits(corrupted)
	info := DecodeISCH(dibits)
	if !info.Valid || info.Location != 0 {
		t.Errorf("expected correction to location 0, got valid=%v loc=%d", info.Valid, info.Location)
	}
}

func TestISCH_RejectsTooManyErrors(t *testing.T) {
	// Flip 9 bits (mask 0x1ff). The (40,9,16) code corrects up to 7 errors;
	// 9-bit corruption lands at distance 9 from every valid codeword, so the
	// decoder must reject it. (A naive 16-bit flip like 0xffff can accidentally
	// land within 7 bits of a *different* codeword due to the code geometry.)
	const target = 0x184229d461
	corrupted := uint64(target) ^ uint64(0x1ff) // 9-bit flip, minDist=9 from all codewords
	dibits := cwToDibits(corrupted)
	info := DecodeISCH(dibits)
	if info.Valid {
		t.Errorf("expected decode failure for 9-bit corruption, got loc=%d", info.Location)
	}
}

func TestISCH_SlotMapping(t *testing.T) {
	// WhichSlot[10] must be 1, not 0 (asymmetric pattern).
	// v=80 → loc=2, chn=2 → pos = 2*4+2 = 10.
	info := DecodeISCH(cwToDibits(0x0a456534c6)) // message 80 → location 10
	if info.Location != 10 {
		t.Fatalf("setup: wrong location %d", info.Location)
	}
	if info.Slot != 1 {
		t.Errorf("location 10 → slot %d, expected 1", info.Slot)
	}
}

// cwToDibits unpacks a 40-bit codeword into 20 dibits (MSB-first).
func cwToDibits(cw uint64) [SyncDibits]p25.Dibit {
	var out [SyncDibits]p25.Dibit
	for i := 0; i < SyncDibits; i++ {
		out[i] = p25.Dibit((cw >> uint(38-2*i)) & 0x3)
	}
	return out
}
