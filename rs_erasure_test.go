package p25

import (
	"reflect"
	"testing"
)

// buildValidCW63x35 fills cw[28..62] with a deterministic data pattern and
// returns the fully-encoded length-63 RS(63,35) codeword (parity at cw[0..27]).
func buildValidCW63x35() [63]uint8 {
	var cw [63]uint8
	for i := 28; i < 63; i++ {
		cw[i] = uint8((i*5 + 1) & 0x3f)
	}
	return RSEncode63x35(cw)
}

// TestRSDecodeWithErasures_FACCHBudgetCrossover proves the budget extension is
// real: with the 9 FACCH punctured-parity positions zero-filled, the
// errors-only RSDecodeN sees 9+e errors and fails at e=6 (9+6=15>14), while the
// erasure path (2*6+9=21<=28) succeeds and recovers the exact codeword.
func TestRSDecodeWithErasures_FACCHBudgetCrossover(t *testing.T) {
	orig := buildValidCW63x35()
	erasures := []int{0, 1, 2, 3, 4, 5, 6, 7, 8}

	for e := 1; e <= 9; e++ {
		recv := orig
		// Puncture: zero the 9 erasure positions.
		for _, p := range erasures {
			recv[p] = 0
		}
		// Corrupt e non-erasure symbols, picked deterministically from cw[9..62].
		for c := 0; c < e; c++ {
			pos := 9 + (c*7+3)%54 // spread across [9,63)
			recv[pos] = orig[pos] ^ uint8((c*13+1)&0x3f|1)
		}

		got, ne, ok := RSDecodeWithErasures(63, 35, recv[:], erasures)
		if !ok {
			t.Fatalf("e=%d: RSDecodeWithErasures failed, want ok", e)
		}
		if !reflect.DeepEqual([]uint8(got), orig[:]) {
			t.Fatalf("e=%d: RSDecodeWithErasures mis-decoded\n got=%v\nwant=%v", e, got, orig[:])
		}
		if ne != e {
			t.Fatalf("e=%d: numErrors=%d, want %d", e, ne, e)
		}

		// Crossover assertion at e=6: errors-only must fail/mis-decode.
		if e == 6 {
			eoGot, _, eoOK := RSDecodeN(63, 35, 14, recv[:])
			if eoOK && reflect.DeepEqual(eoGot, orig[:]) {
				t.Fatalf("e=6: errors-only RSDecodeN unexpectedly succeeded (9+6=15>14 errors should fail)")
			}
			t.Logf("e=6 CROSSOVER: errors-only RSDecodeN ok=%v (correct=%v); erasure path ok=true correct=true",
				eoOK, eoOK && reflect.DeepEqual(eoGot, orig[:]))
		}
	}
}

// TestRSDecodeWithErasures_SACCHBudget sweeps the 6-erasure SACCH case up to the
// edge of the budget: 2*11+6=28<=28 succeeds, e=12 (2*12+6=30>28) fails.
func TestRSDecodeWithErasures_SACCHBudget(t *testing.T) {
	orig := buildValidCW63x35()
	erasures := []int{0, 1, 2, 3, 4, 5}

	for e := 1; e <= 11; e++ {
		recv := orig
		for _, p := range erasures {
			recv[p] = 0
		}
		for c := 0; c < e; c++ {
			pos := 6 + (c*9+5)%57
			recv[pos] = orig[pos] ^ uint8((c*11+3)&0x3f|1)
		}
		got, ne, ok := RSDecodeWithErasures(63, 35, recv[:], erasures)
		if !ok {
			t.Fatalf("e=%d: RSDecodeWithErasures failed, want ok", e)
		}
		if !reflect.DeepEqual([]uint8(got), orig[:]) {
			t.Fatalf("e=%d: mis-decoded", e)
		}
		if ne != e {
			t.Fatalf("e=%d: numErrors=%d, want %d", e, ne, e)
		}
	}

	// e=12 exceeds the budget (2*12+6=30>28): must fail.
	recv := orig
	for _, p := range erasures {
		recv[p] = 0
	}
	for c := 0; c < 12; c++ {
		pos := 6 + (c*9+5)%57
		recv[pos] = orig[pos] ^ uint8((c*11+3)&0x3f|1)
	}
	if _, _, ok := RSDecodeWithErasures(63, 35, recv[:], erasures); ok {
		t.Fatalf("e=12: expected failure (2*12+6=30>28), got ok")
	}
}

// TestRSDecodeWithErasures_NoErasuresMatchesRSDecodeN is a regression guard: an
// empty erasure list must produce identical results to RSDecodeN.
func TestRSDecodeWithErasures_NoErasuresMatchesRSDecodeN(t *testing.T) {
	orig := buildValidCW63x35()
	for e := 1; e <= 14; e++ {
		recv := orig
		for c := 0; c < e; c++ {
			pos := (c*3 + 1) % 63
			recv[pos] = orig[pos] ^ uint8((c*7+1)&0x3f|1)
		}
		gotE, neE, okE := RSDecodeWithErasures(63, 35, recv[:], nil)
		gotN, neN, okN := RSDecodeN(63, 35, 14, recv[:])
		if okE != okN {
			t.Fatalf("e=%d: ok mismatch erasure=%v rsdecoden=%v", e, okE, okN)
		}
		if okN {
			if !reflect.DeepEqual([]uint8(gotE), gotN) {
				t.Fatalf("e=%d: corrected codeword mismatch", e)
			}
			if neE != neN {
				t.Fatalf("e=%d: nerr mismatch erasure=%d rsdecoden=%d", e, neE, neN)
			}
		}
	}
}

// TestRSDecodeWithErasures_PureErasuresNoErrors proves the punctured-parity
// values are reconstructed from erasures alone with no other channel errors.
func TestRSDecodeWithErasures_PureErasuresNoErrors(t *testing.T) {
	orig := buildValidCW63x35()
	erasures := []int{0, 1, 2, 3, 4, 5, 6, 7, 8}
	recv := orig
	for _, p := range erasures {
		recv[p] = 0
	}
	got, ne, ok := RSDecodeWithErasures(63, 35, recv[:], erasures)
	if !ok {
		t.Fatalf("pure-erasure decode failed")
	}
	if !reflect.DeepEqual([]uint8(got), orig[:]) {
		t.Fatalf("pure-erasure mis-decoded\n got=%v\nwant=%v", got, orig[:])
	}
	if ne != 0 {
		t.Fatalf("pure-erasure numErrors=%d, want 0", ne)
	}
}
