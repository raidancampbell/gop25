package p25

// Reed-Solomon over GF(2^6), primitive polynomial x^6+x+1.
//
// Two RS codes are used in P25 Phase 1:
//
//   RS(24,12,13) — Link Control Word (LDU1), Encryption Sync (LDU2), TDUlc.
//     n=24, k=12, t=6, generator g(x) = ∏(x-α^i, i=1..12).
//
//   RS(36,20,17) — Header Data Unit (HDU).
//     n=36, k=20, t=8, generator g(x) = ∏(x-α^i, i=1..16).

const (
	rsN = 24 // LC codeword length
	rsK = 12 // LC data symbols
	rsT = 6  // LC error correction capability

	rsHDUN = 36 // HDU codeword length
	rsHDUK = 20 // HDU data symbols
	rsHDUT = 8  // HDU error correction capability
)

// rsGenPoly: RS(24,12) generator g(x) = ∏(x-α^i, i=1..12), degree 12.
var rsGenPoly [rsN-rsK+1]uint8

// rsHDUGenPoly: RS(36,20) generator g(x) = ∏(x-α^i, i=1..16), degree 16.
var rsHDUGenPoly [rsHDUN-rsHDUK+1]uint8

func init() {
	// Build RS(24,12) generator polynomial.
	poly := make([]uint8, 1)
	poly[0] = 1
	for i := 1; i <= rsN-rsK; i++ {
		root := gfExp[i%63]
		next := make([]uint8, len(poly)+1)
		for j, c := range poly {
			next[j+1] ^= c
			next[j] ^= gfMul(c, root)
		}
		poly = next
	}
	copy(rsGenPoly[:], poly)

	// Build RS(36,20) generator polynomial (roots α^1 … α^16).
	poly2 := make([]uint8, 1)
	poly2[0] = 1
	for i := 1; i <= rsHDUN-rsHDUK; i++ {
		root := gfExp[i%63]
		next := make([]uint8, len(poly2)+1)
		for j, c := range poly2 {
			next[j+1] ^= c
			next[j] ^= gfMul(c, root)
		}
		poly2 = next
	}
	copy(rsHDUGenPoly[:], poly2)
}

// rsEncode encodes k=12 data symbols into a systematic RS(24,12) codeword.
//
// The message polynomial M(x) = data[0]*x^(k-1) + data[1]*x^(k-2) + ... + data[k-1].
// The codeword C(x) = M(x)*x^(n-k) + R(x), where R(x) = M(x)*x^(n-k) mod g(x).
//
// Layout:
//
//	cw[0..n-k-1] = R(x) coefficients (parity, x^0..x^(n-k-1))
//	cw[n-k..n-1] = message coefficients: cw[n-k+j] = coeff of x^(n-k+j) in M(x)*x^(n-k)
//	             = data[k-1-j]
//
// This ensures C(α^j) = 0 for j=1..2t.
func rsEncode(data [rsK]uint8) [rsN]uint8 {
	var cw [rsN]uint8

	// Build the shifted message M(x)*x^(n-k) as a polynomial of degree n-1.
	// Coefficient of x^i is stored in msg[i].
	var msg [rsN]uint8
	for i := 0; i < rsK; i++ {
		// data[i] is coefficient of x^(k-1-i) in M(x),
		// so coefficient of x^(n-1-i) in M(x)*x^(n-k).
		msg[rsN-1-i] = data[i]
	}

	// Compute R(x) = msg mod g(x) using polynomial long division.
	// Work on a copy since we modify it.
	rem := make([]uint8, rsN)
	copy(rem, msg[:])
	for i := rsN - 1; i >= rsN-rsK; i-- {
		coeff := rem[i]
		if coeff == 0 {
			continue
		}
		// Subtract coeff * g(x) * x^(i - deg(g))
		shift := i - (rsN - rsK) // = i - 12
		for j := 0; j <= rsN-rsK; j++ {
			rem[shift+j] ^= gfMul(coeff, rsGenPoly[j])
		}
	}

	// Parity = remainder (degree < n-k)
	copy(cw[:rsN-rsK], rem[:rsN-rsK])
	// Message symbols in high positions
	for i := 0; i < rsK; i++ {
		cw[rsN-rsK+i] = msg[rsN-rsK+i]
	}
	return cw
}

// rsDecode decodes a received RS(24,12) codeword, correcting up to t=6 symbol
// errors. Returns the 12 data symbols and true on success, or zeroes and false
// if uncorrectable.
func rsDecode(received [rsN]uint8) ([rsK]uint8, bool) {
	// 1. Compute 2t=12 syndromes: S_j = R(α^j) for j=1..2t.
	var syndromes [2 * rsT]uint8
	hasError := false
	for j := 0; j < 2*rsT; j++ {
		var s uint8
		alpha := gfExp[(j+1)%63]
		x := uint8(1)
		for i := 0; i < rsN; i++ {
			s ^= gfMul(received[i], x)
			x = gfMul(x, alpha)
		}
		syndromes[j] = s
		if s != 0 {
			hasError = true
		}
	}
	if !hasError {
		var data [rsK]uint8
		for i := 0; i < rsK; i++ {
			data[i] = received[rsN-1-i]
		}
		return data, true
	}

	// 2. Berlekamp-Massey to find error locator polynomial Λ(x).
	lambda := make([]uint8, 1)
	lambda[0] = 1
	b := make([]uint8, 1)
	b[0] = 1

	L, x := 0, 1
	for n := 0; n < 2*rsT; n++ {
		// Compute discrepancy d = S_n + sum(lambda_i * S_{n-i})
		d := syndromes[n]
		for i := 1; i < len(lambda); i++ {
			if n-i >= 0 {
				d ^= gfMul(lambda[i], syndromes[n-i])
			}
		}
		b = append([]uint8{0}, b...) // b = x·b
		if d == 0 {
			x++
			continue
		}
		t2 := make([]uint8, len(lambda))
		copy(t2, lambda)
		scale := d
		for i, bv := range b {
			if i < len(lambda) {
				lambda[i] ^= gfMul(scale, bv)
			} else {
				lambda = append(lambda, gfMul(scale, bv))
			}
		}
		if 2*L <= n {
			L = n + 1 - L
			b = t2
			invD := gfInv(d)
			for i := range b {
				b[i] = gfMul(b[i], invD)
			}
		}
		x = 1
	}

	if L > rsT {
		return [rsK]uint8{}, false
	}

	// 3. Chien search: find error locations (roots of Λ(x)).
	errPos := make([]int, 0, L)
	for i := 0; i < rsN; i++ {
		// Evaluate Λ(α^{-i}) = Λ at α^{63-i mod 63}
		alphaInvI := uint8(0)
		if i == 0 {
			alphaInvI = 1
		} else {
			alphaInvI = gfExp[(63-i%63)%63]
		}
		val := uint8(0)
		xi := uint8(1)
		for _, lc := range lambda {
			val ^= gfMul(lc, xi)
			xi = gfMul(xi, alphaInvI)
		}
		if val == 0 {
			errPos = append(errPos, i)
		}
	}
	if len(errPos) != L {
		return [rsK]uint8{}, false
	}

	// 4. Forney algorithm: compute error magnitudes.
	// Ω(x) = S(x)·Λ(x) mod x^{2t}  (error evaluator polynomial)
	// Λ'(x) = formal derivative of Λ(x) (every other term)
	// e_k = -Ω(α^{-pos_k}) / Λ'(α^{-pos_k})
	// In GF(2), negation is identity.

	// Compute Ω = S*Λ mod x^{2t}.
	omega := make([]uint8, 2*rsT)
	for i := 0; i < 2*rsT; i++ {
		for j := 0; j < len(lambda) && i-j >= 0; j++ {
			omega[i] ^= gfMul(syndromes[i-j], lambda[j])
		}
	}

	// Λ' = odd-indexed terms of Λ (GF(2) formal derivative: d/dx x^n = n*x^{n-1}, n odd → 1).
	lambdaPrime := make([]uint8, len(lambda))
	for i := 1; i < len(lambda); i += 2 {
		lambdaPrime[i-1] = lambda[i]
	}

	errs := make([]uint8, rsN)
	for _, pos := range errPos {
		alphaInvPos := uint8(0)
		if pos == 0 {
			alphaInvPos = 1
		} else {
			alphaInvPos = gfExp[(63-pos%63)%63]
		}

		// Evaluate Ω(α^{-pos})
		omegaVal := uint8(0)
		xi := uint8(1)
		for _, o := range omega {
			omegaVal ^= gfMul(o, xi)
			xi = gfMul(xi, alphaInvPos)
		}

		// Evaluate Λ'(α^{-pos})
		lpVal := uint8(0)
		xi = 1
		for _, lp := range lambdaPrime {
			lpVal ^= gfMul(lp, xi)
			xi = gfMul(xi, alphaInvPos)
		}

		if lpVal == 0 {
			return [rsK]uint8{}, false
		}
		errs[pos] = gfMul(omegaVal, gfInv(lpVal))
	}

	// 5. Apply corrections.
	corrected := received
	for i, e := range errs {
		corrected[i] ^= e
	}

	// Verify syndromes are zero after correction.
	for j := 0; j < 2*rsT; j++ {
		var s uint8
		alpha := gfExp[(j+1)%63]
		xi := uint8(1)
		for i := 0; i < rsN; i++ {
			s ^= gfMul(corrected[i], xi)
			xi = gfMul(xi, alpha)
		}
		if s != 0 {
			return [rsK]uint8{}, false
		}
	}

	var data [rsK]uint8
	for i := 0; i < rsK; i++ {
		data[i] = corrected[rsN-1-i]
	}
	return data, true
}

// rsDecode63 decodes a shortened systematic RS code over GF(2^6) where the
// 24 received hexbits are placed at HB[39..62] of a virtual length-63
// codeword (HB[0..38] zero-padded), matching op25's layout. parity is the
// number of parity hexbits (n-k of the shortened code):
//
//	LDU1 LC: RS(24,12,13)  parity=12  t=6
//	LDU2 ES: RS(24,16,9)   parity=8   t=4
//
// Op25/ezpwd treats HB[i] as the coefficient of x^{62-i}; rsDecodeGenericN
// treats received[i] as the coefficient of x^i. We convert by reversing.
//
// Returns the 24 corrected hexbits and the number of corrected symbols.
func rsDecode63(hb [24]uint8, parity int) (corrected [24]uint8, nerr int, ok bool) {
	t := parity / 2
	var cw [63]uint8
	for i, h := range hb {
		cw[23-i] = h
	}
	dec, ne, ok := rsDecodeGenericN(63, 63-parity, t, cw[:])
	if !ok {
		return hb, 0, false
	}
	// Shortened-code invariant: the 39 phantom positions cw[24..62] are known
	// zero (only cw[0..23] are transmitted). A correct shortened-RS decode must
	// leave them zero. When the received word has MORE than t errors it is
	// uncorrectable, but bounded-distance decoding can still converge on a
	// different valid length-63 codeword by "spending" corrections in the
	// phantom region; its syndromes verify clean, so rsDecodeGenericN returns
	// ok=true with garbage data. Rejecting any decode that dirtied the padding
	// turns those false successes back into clean failures. This is the root
	// cause of clear P25 calls being tagged with spurious encryption
	// algorithms/keys (garbage AlgoID/KeyID from a miscorrected LDU2 ES word).
	for i := 24; i < 63; i++ {
		if dec[i] != 0 {
			return hb, 0, false
		}
	}
	for i := range corrected {
		corrected[i] = dec[23-i]
	}
	return corrected, ne, true
}

// rsEncode63 computes the RS parity for a partially-filled 24-hexbit array
// (data hexbits in hb[0..24-parity-1], parity slots ignored). Returns the
// full hb with parity filled in. Used by tests to construct valid codewords.
func rsEncode63(hb [24]uint8, parity int) [24]uint8 {
	// Build generator g(x) = ∏(x-α^i) for i=1..parity.
	gen := []uint8{1}
	for i := 1; i <= parity; i++ {
		root := gfExp[i%63]
		next := make([]uint8, len(gen)+1)
		for j, c := range gen {
			next[j+1] ^= c
			next[j] ^= gfMul(c, root)
		}
		gen = next
	}
	// Place data at high coefficients of a degree-62 polynomial:
	// hb[i] (i < 24-parity) → coeff of x^{23-i}; parity at x^{parity-1..0}.
	var msg [63]uint8
	for i := 0; i < 24-parity; i++ {
		msg[23-i] = hb[i]
	}
	rem := make([]uint8, 63)
	copy(rem, msg[:])
	for i := 62; i >= parity; i-- {
		c := rem[i]
		if c == 0 {
			continue
		}
		shift := i - parity
		for j := 0; j <= parity; j++ {
			rem[shift+j] ^= gfMul(c, gen[j])
		}
	}
	out := hb
	for i := 0; i < parity; i++ {
		out[24-parity+i] = rem[parity-1-i]
	}
	return out
}

// RSEncode63x35 fills the 28 parity symbols of a length-63 RS codeword over
// GF(2^6) (k=35, t=14, roots alpha^1..alpha^28), given the 35 data symbols
// already placed at cw[28..62]. Returns the full codeword with parity at
// cw[0..27]. Convention: received[i] is the coefficient of x^i, matching
// RSDecodeN — so C(alpha^j)=0 for j=1..28. Exported for phase2 ACCH test
// synthesis (the inverse of decodeACCHBytes). Generalizes rsEncode63.
func RSEncode63x35(cw [63]uint8) [63]uint8 {
	const n, k = 63, 35
	const parity = n - k // 28

	// Build generator g(x) = prod(x - alpha^i, i=1..28), degree 28.
	gen := []uint8{1}
	for i := 1; i <= parity; i++ {
		root := gfExp[i%63]
		next := make([]uint8, len(gen)+1)
		for j, c := range gen {
			next[j+1] ^= c
			next[j] ^= gfMul(c, root)
		}
		gen = next
	}

	// Message polynomial M(x)*x^(n-k): data lives at the high coefficients
	// (cw[28..62] are the coeffs of x^28..x^62), parity slots cw[0..27] zero.
	rem := make([]uint8, n)
	for i := parity; i < n; i++ {
		rem[i] = cw[i]
	}

	// R(x) = M(x)*x^(n-k) mod g(x) via polynomial long division.
	for i := n - 1; i >= parity; i-- {
		c := rem[i]
		if c == 0 {
			continue
		}
		shift := i - parity
		for j := 0; j <= parity; j++ {
			rem[shift+j] ^= gfMul(c, gen[j])
		}
	}

	out := cw
	for i := 0; i < parity; i++ {
		out[i] = rem[i] // parity remainder occupies x^0..x^27
	}
	return out
}

// RSDecodeN decodes a received RS codeword of length n over GF(2^6) with
// k data symbols, correcting up to t=(n-k)/2 symbol errors. Returns the
// corrected codeword, number of corrected symbols, and success flag.
// Exported for use by the phase2 ESS decoder.
func RSDecodeN(n, k, t int, received []uint8) ([]uint8, int, bool) {
	return rsDecodeGenericN(n, k, t, received)
}

// RSDecodeWithErasures decodes a received RS codeword of length n over GF(2^6)
// with k data symbols, treating the positions listed in erasures as ERASURES
// (location known, value unknown -> cost 1 budget unit each) and any remaining
// channel errors as unknown errors (cost 2 each). The errata identity is
//
//	2*(unknown errors) + (erasures) <= 2t,  t = (n-k)/2.
//
// The erasures slice must contain distinct codeword indices in [0,n); out-of-range
// or duplicate positions are ignored/deduped.
//
// This is the standard errors-and-erasures (Forney) extension of the
// errors-only rsDecodeGenericN and reuses its EXACT GF conventions:
// received[i] is the coeff of x^i; syndromes S_{j+1} use alpha=gfExp[(j+1)%63];
// the Chien inverse-eval uses alphaInvI=gfExp[(63-i%63)%63]; Forney builds
// Omega=(S*errata)mod x^{2t} with the formal derivative (odd-degree) of the
// errata locator. The Berlekamp-Massey step is SEEDED with the erasure locator
// Gamma (Lambda=B=Gamma, L=nu) so it converges directly to the full errata
// locator Psi without a separate modified-syndrome / Lambda*Gamma step.
// Returns (corrected codeword length n, numErrors NOT counting erasures, ok).
// RSDecodeN is left untouched for its existing callers.
func RSDecodeWithErasures(n, k int, received []uint8, erasures []int) ([]uint8, int, bool) {
	t := (n - k) / 2

	// Sanitize erasures: dedupe and ensure all positions are in [0,n).
	seen := make(map[int]bool, len(erasures))
	validErasures := make([]int, 0, len(erasures))
	for _, p := range erasures {
		if p >= 0 && p < n && !seen[p] {
			seen[p] = true
			validErasures = append(validErasures, p)
		}
	}
	erasures = validErasures

	// 1. Syndromes S_1..S_{2t}, S_{j+1}=R(alpha^{j+1}) (same as rsDecodeGenericN).
	syndromes := make([]uint8, 2*t)
	for j := range 2 * t {
		var s uint8
		alpha := gfExp[(j+1)%63]
		x := uint8(1)
		for i := range n {
			s ^= gfMul(received[i], x)
			x = gfMul(x, alpha)
		}
		syndromes[j] = s
	}
	// With no erasures and zero syndromes the word is already a codeword.
	// (When erasures are declared, the zero-filled word may have small/zero
	// syndromes yet still need the punctured values reconstructed, so do NOT
	// early-return in that case.)
	if len(erasures) == 0 {
		allZero := true
		for _, s := range syndromes {
			if s != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			out := make([]uint8, n)
			copy(out, received)
			return out, 0, true
		}
	}

	// 2. Erasure locator Gamma(x) = prod_{p in erasures} (1 + alpha^p * x).
	//    Built incrementally; gamma[d] is the coeff of x^d.
	gamma := []uint8{1}
	for _, p := range erasures {
		xp := gfExp[((p%63)+63)%63] // alpha^p
		next := make([]uint8, len(gamma)+1)
		for d, c := range gamma {
			next[d] ^= c              // * 1
			next[d+1] ^= gfMul(c, xp) // * (alpha^p * x)
		}
		gamma = next
	}

	nu := len(erasures)

	// 3. Berlekamp-Massey SEEDED with the erasure locator. Initializing both
	//    Lambda and B to Gamma and L to nu, then iterating the discrepancy over
	//    the ORIGINAL syndromes from index nu, yields the full ERRATA locator
	//    Psi directly (deg = nu + #real-errors), so no separate Lambda*Gamma
	//    multiply is needed. The L bookkeeping uses the standard
	//    "2L <= nn + nu" gate (Blahut errors-and-erasures form). This is the
	//    same BM loop shape as rsDecodeGenericN, just pre-seeded.
	psi := make([]uint8, len(gamma))
	copy(psi, gamma)
	b := make([]uint8, len(gamma))
	copy(b, gamma)
	L := nu
	for nn := nu; nn < 2*t; nn++ {
		d := syndromes[nn]
		for i := 1; i < len(psi); i++ {
			if nn-i >= 0 {
				d ^= gfMul(psi[i], syndromes[nn-i])
			}
		}
		b = append([]uint8{0}, b...)
		if d == 0 {
			continue
		}
		t2 := make([]uint8, len(psi))
		copy(t2, psi)
		for i, bv := range b {
			if i < len(psi) {
				psi[i] ^= gfMul(d, bv)
			} else {
				psi = append(psi, gfMul(d, bv))
			}
		}
		if 2*L <= nn+nu {
			L = nn + 1 + nu - L
			invD := gfInv(d)
			b = make([]uint8, len(t2))
			for i := range t2 {
				b[i] = gfMul(t2[i], invD)
			}
		}
	}
	// L is the total errata count (nu erasures + real errors). The real-error
	// count is L - nu; the budget identity 2*(L-nu) + nu <= 2t must hold.
	numErrors := L - nu
	if numErrors < 0 || 2*numErrors+nu > 2*t {
		return nil, 0, false
	}

	// 4. Chien search over the errata locator Psi for all nu+numErrors roots.
	errataPos := make([]int, 0, L)
	for i := range n {
		alphaInvI := uint8(1)
		if i != 0 {
			alphaInvI = gfExp[(63-i%63)%63]
		}
		var val uint8
		xi := uint8(1)
		for _, c := range psi {
			val ^= gfMul(c, xi)
			xi = gfMul(xi, alphaInvI)
		}
		if val == 0 {
			errataPos = append(errataPos, i)
		}
	}
	if len(errataPos) != L {
		return nil, 0, false
	}

	// 5. Forney: Omega = (S * Psi) mod x^{2t}; Psi' = formal derivative of Psi
	//    (odd-degree terms). magnitude = Omega(a^-pos)/Psi'(a^-pos).
	omega := make([]uint8, 2*t)
	for i := range 2 * t {
		for j := 0; j < len(psi) && i-j >= 0; j++ {
			omega[i] ^= gfMul(syndromes[i-j], psi[j])
		}
	}
	psiPrime := make([]uint8, len(psi))
	for i := 1; i < len(psi); i += 2 {
		psiPrime[i-1] = psi[i]
	}

	corrected := make([]uint8, n)
	copy(corrected, received)
	for _, pos := range errataPos {
		alphaInvPos := uint8(1)
		if pos != 0 {
			alphaInvPos = gfExp[(63-pos%63)%63]
		}
		var ov, ppv uint8
		xi := uint8(1)
		for _, o := range omega {
			ov ^= gfMul(o, xi)
			xi = gfMul(xi, alphaInvPos)
		}
		xi = 1
		for _, p := range psiPrime {
			ppv ^= gfMul(p, xi)
			xi = gfMul(xi, alphaInvPos)
		}
		if ppv == 0 {
			return nil, 0, false
		}
		corrected[pos] ^= gfMul(ov, gfInv(ppv))
	}

	// 6. Verify all 2t syndromes of the corrected word are zero.
	for j := range 2 * t {
		var s uint8
		alpha := gfExp[(j+1)%63]
		xi := uint8(1)
		for i := range n {
			s ^= gfMul(corrected[i], xi)
			xi = gfMul(xi, alpha)
		}
		if s != 0 {
			return nil, 0, false
		}
	}
	return corrected, numErrors, true
}

// rsDecodeGenericN is rsDecodeGeneric returning (corrected codeword, nerr, ok).
func rsDecodeGenericN(n, k, t int, received []uint8) ([]uint8, int, bool) {
	syndromes := make([]uint8, 2*t)
	hasError := false
	for j := range 2 * t {
		var s uint8
		alpha := gfExp[(j+1)%63]
		x := uint8(1)
		for i := range n {
			s ^= gfMul(received[i], x)
			x = gfMul(x, alpha)
		}
		syndromes[j] = s
		if s != 0 {
			hasError = true
		}
	}
	if !hasError {
		out := make([]uint8, n)
		copy(out, received)
		return out, 0, true
	}

	lambda := []uint8{1}
	b := []uint8{1}
	L := 0
	for nn := range 2 * t {
		d := syndromes[nn]
		for i := 1; i < len(lambda); i++ {
			if nn-i >= 0 {
				d ^= gfMul(lambda[i], syndromes[nn-i])
			}
		}
		b = append([]uint8{0}, b...)
		if d == 0 {
			continue
		}
		t2 := make([]uint8, len(lambda))
		copy(t2, lambda)
		for i, bv := range b {
			if i < len(lambda) {
				lambda[i] ^= gfMul(d, bv)
			} else {
				lambda = append(lambda, gfMul(d, bv))
			}
		}
		if 2*L <= nn {
			L = nn + 1 - L
			invD := gfInv(d)
			b = make([]uint8, len(t2))
			for i := range t2 {
				b[i] = gfMul(t2[i], invD)
			}
		}
	}
	if L > t {
		return nil, 0, false
	}

	errPos := make([]int, 0, L)
	for i := range n {
		alphaInvI := uint8(1)
		if i != 0 {
			alphaInvI = gfExp[(63-i%63)%63]
		}
		var val uint8
		xi := uint8(1)
		for _, lc := range lambda {
			val ^= gfMul(lc, xi)
			xi = gfMul(xi, alphaInvI)
		}
		if val == 0 {
			errPos = append(errPos, i)
		}
	}
	if len(errPos) != L {
		return nil, 0, false
	}

	omega := make([]uint8, 2*t)
	for i := range 2 * t {
		for j := 0; j < len(lambda) && i-j >= 0; j++ {
			omega[i] ^= gfMul(syndromes[i-j], lambda[j])
		}
	}
	lambdaPrime := make([]uint8, len(lambda))
	for i := 1; i < len(lambda); i += 2 {
		lambdaPrime[i-1] = lambda[i]
	}

	corrected := make([]uint8, n)
	copy(corrected, received)
	for _, pos := range errPos {
		alphaInvPos := uint8(1)
		if pos != 0 {
			alphaInvPos = gfExp[(63-pos%63)%63]
		}
		var ov, lpv uint8
		xi := uint8(1)
		for _, o := range omega {
			ov ^= gfMul(o, xi)
			xi = gfMul(xi, alphaInvPos)
		}
		xi = 1
		for _, lp := range lambdaPrime {
			lpv ^= gfMul(lp, xi)
			xi = gfMul(xi, alphaInvPos)
		}
		if lpv == 0 {
			return nil, 0, false
		}
		corrected[pos] ^= gfMul(ov, gfInv(lpv))
	}

	for j := range 2 * t {
		var s uint8
		alpha := gfExp[(j+1)%63]
		xi := uint8(1)
		for i := range n {
			s ^= gfMul(corrected[i], xi)
			xi = gfMul(xi, alpha)
		}
		if s != 0 {
			return nil, 0, false
		}
	}
	return corrected, L, true
}

// gfInv returns the multiplicative inverse of a in GF(2^6).
func gfInv(a uint8) uint8 {
	if a == 0 {
		return 0
	}
	return gfExp[(63-int(gfLog[a]))%63]
}

// rsEncodeHDU encodes k=20 HDU data symbols into a systematic RS(36,20) codeword.
// Layout: cw[0..15] = parity (R(x) coefficients), cw[16..35] = data (high to low).
func rsEncodeHDU(data [rsHDUK]uint8) [rsHDUN]uint8 {
	return rsEncodeGeneric(rsHDUN, rsHDUK, rsHDUGenPoly[:], data[:])
}

// rsDecodeHDU decodes a received RS(36,20) codeword, correcting up to t=8 symbol
// errors. Returns the 20 data symbols and true, or zeroes and false.
func rsDecodeHDU(received [rsHDUN]uint8) ([rsHDUK]uint8, bool) {
	data, ok := rsDecodeGeneric(rsHDUN, rsHDUK, rsHDUT, rsHDUGenPoly[:], received[:])
	if !ok {
		return [rsHDUK]uint8{}, false
	}
	var out [rsHDUK]uint8
	copy(out[:], data)
	return out, true
}

// rsEncodeGeneric is the shared systematic RS encoder for any (n,k) over GF(2^6).
// genPoly must have degree n-k (length n-k+1).
func rsEncodeGeneric(n, k int, genPoly []uint8, data []uint8) [rsHDUN]uint8 {
	// Build M(x)·x^(n-k) with message in high positions.
	msg := make([]uint8, n)
	for i := 0; i < k; i++ {
		msg[n-1-i] = data[i]
	}
	// Remainder R(x) = M(x)·x^(n-k) mod g(x).
	rem := make([]uint8, n)
	copy(rem, msg)
	for i := n - 1; i >= n-k; i-- {
		c := rem[i]
		if c == 0 {
			continue
		}
		shift := i - (n - k)
		for j := 0; j <= n-k; j++ {
			rem[shift+j] ^= gfMul(c, genPoly[j])
		}
	}
	var cw [rsHDUN]uint8
	copy(cw[:n-k], rem[:n-k]) // parity
	for i := 0; i < k; i++ {
		cw[n-k+i] = msg[n-k+i] // data
	}
	return cw
}

// rsDecodeGeneric is the shared RS decoder for any (n,k,t) over GF(2^6).
func rsDecodeGeneric(n, k, t int, genPoly []uint8, received []uint8) ([]uint8, bool) {
	// 1. Syndromes S_j = R(α^j) for j=1..2t.
	syndromes := make([]uint8, 2*t)
	hasError := false
	for j := 0; j < 2*t; j++ {
		var s uint8
		alpha := gfExp[(j+1)%63]
		x := uint8(1)
		for i := 0; i < n; i++ {
			s ^= gfMul(received[i], x)
			x = gfMul(x, alpha)
		}
		syndromes[j] = s
		if s != 0 {
			hasError = true
		}
	}
	if !hasError {
		data := make([]uint8, k)
		for i := 0; i < k; i++ {
			data[i] = received[n-1-i]
		}
		return data, true
	}

	// 2. Berlekamp-Massey.
	lambda := []uint8{1}
	b := []uint8{1}
	L, xx := 0, 1
	for nn := 0; nn < 2*t; nn++ {
		d := syndromes[nn]
		for i := 1; i < len(lambda); i++ {
			if nn-i >= 0 {
				d ^= gfMul(lambda[i], syndromes[nn-i])
			}
		}
		b = append([]uint8{0}, b...)
		if d == 0 {
			xx++
			continue
		}
		t2 := make([]uint8, len(lambda))
		copy(t2, lambda)
		scale := d
		for i, bv := range b {
			if i < len(lambda) {
				lambda[i] ^= gfMul(scale, bv)
			} else {
				lambda = append(lambda, gfMul(scale, bv))
			}
		}
		if 2*L <= nn {
			L = nn + 1 - L
			b = t2
			invD := gfInv(d)
			for i := range b {
				b[i] = gfMul(b[i], invD)
			}
		}
		xx = 1
	}
	_ = xx

	if L > t {
		return nil, false
	}

	// 3. Chien search.
	errPos := make([]int, 0, L)
	for i := 0; i < n; i++ {
		aInv := uint8(1)
		if i != 0 {
			aInv = gfExp[(63-i%63)%63]
		}
		val := uint8(0)
		xi := uint8(1)
		for _, lc := range lambda {
			val ^= gfMul(lc, xi)
			xi = gfMul(xi, aInv)
		}
		if val == 0 {
			errPos = append(errPos, i)
		}
	}
	if len(errPos) != L {
		return nil, false
	}

	// 4. Forney.
	omega := make([]uint8, 2*t)
	for i := 0; i < 2*t; i++ {
		for j := 0; j < len(lambda) && i-j >= 0; j++ {
			omega[i] ^= gfMul(syndromes[i-j], lambda[j])
		}
	}
	lambdaPrime := make([]uint8, len(lambda))
	for i := 1; i < len(lambda); i += 2 {
		lambdaPrime[i-1] = lambda[i]
	}
	errs := make([]uint8, n)
	for _, pos := range errPos {
		aInv := uint8(1)
		if pos != 0 {
			aInv = gfExp[(63-pos%63)%63]
		}
		omegaVal := uint8(0)
		xi := uint8(1)
		for _, o := range omega {
			omegaVal ^= gfMul(o, xi)
			xi = gfMul(xi, aInv)
		}
		lpVal := uint8(0)
		xi = 1
		for _, lp := range lambdaPrime {
			lpVal ^= gfMul(lp, xi)
			xi = gfMul(xi, aInv)
		}
		if lpVal == 0 {
			return nil, false
		}
		errs[pos] = gfMul(omegaVal, gfInv(lpVal))
	}

	// 5. Correct and verify.
	corrected := make([]uint8, n)
	copy(corrected, received)
	for i, e := range errs {
		corrected[i] ^= e
	}
	for j := 0; j < 2*t; j++ {
		var s uint8
		alpha := gfExp[(j+1)%63]
		xi := uint8(1)
		for i := 0; i < n; i++ {
			s ^= gfMul(corrected[i], xi)
			xi = gfMul(xi, alpha)
		}
		if s != 0 {
			return nil, false
		}
	}

	data := make([]uint8, k)
	for i := 0; i < k; i++ {
		data[i] = corrected[n-1-i]
	}
	return data, true
}

