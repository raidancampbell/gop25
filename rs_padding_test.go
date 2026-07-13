package p25

import (
	"math/rand"
	"testing"
)

// TestRSDecode63_RejectsPaddingLeak is the regression for clear P25 calls being
// tagged with spurious encryption algorithms/keys.
//
// rsDecode63 embeds a shortened RS(24,k) code into a length-63 codeword whose
// positions cw[24..62] are phantom zero padding (never transmitted). When a
// received word has MORE than t errors it is uncorrectable, but the underlying
// bounded-distance decoder can still converge on a DIFFERENT valid length-63
// codeword by placing "corrections" in the phantom region. Its syndromes verify
// clean, so the raw decoder returns ok=true with garbage data — on the LDU2 ES
// path that garbage becomes a bogus AlgoID/KeyID and the call is logged as
// encrypted. rsDecode63 must reject any decode that dirtied the padding.
//
// This test deterministically constructs real padding-leak words (confirming the
// raw decoder would accept them) and asserts rsDecode63 now fails them cleanly.
func TestRSDecode63_RejectsPaddingLeak(t *testing.T) {
	for _, parity := range []int{8, 12} { // ES RS(24,16,9) t=4; LC RS(24,12,13) t=6
		tcap := parity / 2
		rng := rand.New(rand.NewSource(int64(parity)))

		var hb [24]uint8 // all-zero data+parity is a valid codeword
		found := 0
		for trial := 0; trial < 200000 && found < 50; trial++ {
			cw := hb
			perm := rng.Perm(24)
			for k := 0; k <= tcap; k++ { // t+1 errors => uncorrectable
				cw[perm[k]] ^= uint8(rng.Intn(63) + 1)
			}

			// Does the RAW decoder accept this over-budget word with dirty padding?
			var emb [63]uint8
			for i, h := range cw {
				emb[23-i] = h
			}
			dec, _, ok := rsDecodeGenericN(63, 63-parity, tcap, emb[:])
			if !ok {
				continue
			}
			dirty := false
			for i := 24; i < 63; i++ {
				if dec[i] != 0 {
					dirty = true
					break
				}
			}
			if !dirty {
				continue // clean padding: true decode or in-window miscorrect, not our target
			}
			found++

			// The raw decoder leaked into the padding. The hardened wrapper must reject.
			if _, _, ok63 := rsDecode63(cw, parity); ok63 {
				t.Fatalf("parity=%d: rsDecode63 accepted a padding-leak miscorrection: %v", parity, cw)
			}
		}
		if found == 0 {
			t.Fatalf("parity=%d: test ineffective — constructed no padding-leak case", parity)
		}
		t.Logf("parity=%d: rsDecode63 rejected %d padding-leak miscorrections", parity, found)
	}
}

// TestRSDecode63_AcceptsValidWithinBudget guards the fix against false negatives:
// a genuinely-transmitted codeword with <= t errors always has zero padding after
// correction, so the new invariant must never reject it.
func TestRSDecode63_AcceptsValidWithinBudget(t *testing.T) {
	for _, parity := range []int{8, 12} {
		tcap := parity / 2
		// Build a valid codeword from arbitrary data hexbits.
		var data [24]uint8
		for i := 0; i < 24-parity; i++ {
			data[i] = uint8((i*11 + 3) & 0x3F)
		}
		cwValid := rsEncode63(data, parity)

		for nerr := 0; nerr <= tcap; nerr++ {
			rx := cwValid
			for e := 0; e < nerr; e++ {
				rx[e] ^= uint8(e + 1)
			}
			got, ne, ok := rsDecode63(rx, parity)
			if !ok {
				t.Fatalf("parity=%d nerr=%d: valid within-budget word rejected", parity, nerr)
			}
			if ne != nerr {
				t.Fatalf("parity=%d nerr=%d: reported %d corrections", parity, nerr, ne)
			}
			if got != cwValid {
				t.Fatalf("parity=%d nerr=%d: wrong data recovered", parity, nerr)
			}
		}
	}
}
