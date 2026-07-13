package phase2

import "testing"

func TestDUIDLookupTableSize(t *testing.T) {
	if len(duidLookup) != 256 {
		t.Fatalf("duidLookup must have 256 entries, got %d", len(duidLookup))
	}
}

func TestExtractDUID(t *testing.T) {
	// All-zero DUID dibits -> codeword 0x00.
	var burst Burst
	if got := extractDUID(burst); got != 0x00 {
		t.Fatalf("all-zero DUID: got 0x%02X want 0x00", got)
	}

	// All-ones DUID dibits at the corrected absolute positions 20/57/142/179
	// (op25 burstp[10/47/132/169] with burstp = &dibits[10]).
	for _, pos := range []int{20, 57, 142, 179} {
		burst.Dibits[pos] = 0x3
	}
	if got := extractDUID(burst); got != 0xFF {
		t.Fatalf("all-ones DUID: got 0x%02X want 0xFF", got)
	}

	// Distinct per-position values prove bit packing & ordering:
	// d0<<6 | d1<<4 | d2<<2 | d3 with d0..d3 = 1,2,3,0 -> 0b01_10_11_00 = 0x6C.
	var b2 Burst
	b2.Dibits[20] = 0x1
	b2.Dibits[57] = 0x2
	b2.Dibits[142] = 0x3
	b2.Dibits[179] = 0x0
	if got := extractDUID(b2); got != 0x6C {
		t.Fatalf("ordered DUID: got 0x%02X want 0x6C", got)
	}
}

func TestClassifyByFEC(t *testing.T) {
	// ClassifyByFEC uses the Golay c0 error sum across all 4 VCW positions
	// to detect voice bursts. Verify with synthetic data:
	//   - All-zero dibits → valid Golay codewords (c0 errs=0) → Burst4V
	//   - Random-looking dibits → high c0 errors → BurstUnknown

	// All-zero burst: Golay(24,12) of zero vector = zero = valid codeword.
	// All 4 VCWs have c0 errs=0, sum=0 ≤ 4 → Burst4V.
	var zeroB Burst
	if got := ClassifyByFEC(zeroB.Dibits); got != Burst4V {
		t.Errorf("all-zero burst: got %v, want Burst4V", got)
	}

	// Random-ish burst: fill with alternating 01/10 pattern which produces
	// high Golay errors. All VCWs should have c0 errs ≈ 3, sum ≈ 12 → BurstUnknown.
	var randB Burst
	for i := range randB.Dibits {
		if i%2 == 0 {
			randB.Dibits[i] = 1
		} else {
			randB.Dibits[i] = 2
		}
	}
	if got := ClassifyByFEC(randB.Dibits); got != BurstUnknown {
		t.Errorf("random burst: got %v, want BurstUnknown", got)
	}
}

func TestClassifyDUID_ControlTypes(t *testing.T) {
	// duidLookup maps the raw 8-bit codeword to op25's burst-type id; classifyDUID
	// then maps that id to our BurstType. We drive classifyDUID with the codewords
	// whose duidLookup value is the control id we care about.
	cases := []struct {
		name string
		id   int16 // op25 duid_lookup result
		want BurstType
	}{
		{"scrambled SACCH (3)", 3, BurstSACCH},
		{"scrambled FACCH (9)", 9, BurstFACCH},
		{"unscrambled SACCH (12)", 12, BurstSACCH},
		{"unscrambled LCCH (13)", 13, BurstLCCH},
		{"unscrambled FACCH (15)", 15, BurstFACCH},
		{"voice 4V (0)", 0, BurstUnknown},
		{"voice 2V (6)", 6, BurstUnknown},
		{"invalid", 5, BurstUnknown},
	}
	for _, tc := range cases {
		// Find a codeword whose duidLookup == tc.id to exercise the real path.
		cw := -1
		for i := 0; i < 256; i++ {
			if duidLookup[i] == tc.id {
				cw = i
				break
			}
		}
		if cw < 0 {
			t.Fatalf("%s: no codeword maps to id %d", tc.name, tc.id)
		}
		if got := classifyDUID(uint8(cw)); got != tc.want {
			t.Errorf("%s: classifyDUID(0x%02X) = %v, want %v", tc.name, cw, got, tc.want)
		}
	}
}

func TestClassify_FECFirstThenDUID(t *testing.T) {
	// A burst whose VCW regions are random will fail ClassifyByFEC (BurstUnknown);
	// with a DUID that decodes to scrambled SACCH (id 3) it must classify SACCH.
	var b Burst
	// Fill with alternating pattern to produce high Golay errors -> BurstUnknown.
	for i := range b.Dibits {
		if i%2 == 0 {
			b.Dibits[i] = 1
		} else {
			b.Dibits[i] = 2
		}
	}
	// Pick a codeword mapping to id 3 and set DUID to that value.
	cw := -1
	for i := 0; i < 256; i++ {
		if duidLookup[i] == 3 {
			cw = i
			break
		}
	}
	if cw < 0 {
		t.Fatal("no codeword maps to id 3")
	}
	b.DUID = uint8(cw)
	// Random VCW regions -> ClassifyByFEC returns BurstUnknown, so Classify
	// falls back to classifyDUID which returns BurstSACCH for id 3.
	if got := Classify(b); got != BurstSACCH {
		t.Fatalf("Classify with DUID id 3 = %v, want BurstSACCH", got)
	}
}
