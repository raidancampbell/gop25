package phase2

// duidLookup maps a raw 8-bit DUID extracted from a Phase 2 burst to a burst
// type in the range 0..15, or -1 (invalid). Every value 0 through 15 appears
// in the table as a minimum-distance decode target; entries that have no
// codeword within the correction radius map to -1.
// Source: op25 p25p2_duid.cc:26-43 (_duid_lookup).
//
// Mapping rationale: each burst has 4 redundant DUID dibits; this table is a
// minimum-distance decoder treating the 8 bits as one codeword.
var duidLookup = [256]int16{
	0, 0, 0, -1, 0, -1, -1, 1, 0, -1, -1, 4, -1, 8, 2, -1,
	0, -1, -1, 1, -1, 1, 1, 1, -1, 3, 9, -1, 5, -1, -1, 1,
	0, -1, -1, 10, -1, 6, 2, -1, -1, 3, 2, -1, 2, -1, 2, 2,
	-1, 3, 7, -1, 11, -1, -1, 1, 3, 3, -1, 3, -1, 3, 2, -1,
	0, -1, -1, 4, -1, 6, 12, -1, -1, 4, 4, 4, 5, -1, -1, 4,
	-1, 13, 7, -1, 5, -1, -1, 1, 5, -1, -1, 4, 5, 5, 5, -1,
	-1, 6, 7, -1, 6, 6, -1, 6, 14, -1, -1, 4, -1, 6, 2, -1,
	7, -1, 7, 7, -1, 6, 7, -1, -1, 3, 7, -1, 5, -1, -1, 15,
	0, -1, -1, 10, -1, 8, 12, -1, -1, 8, 9, -1, 8, 8, -1, 8,
	-1, 13, 9, -1, 11, -1, -1, 1, 9, -1, 9, 9, -1, 8, 9, -1,
	-1, 10, 10, 10, 11, -1, -1, 10, 14, -1, -1, 10, -1, 8, 2, -1,
	11, -1, -1, 10, 11, 11, 11, -1, -1, 3, 9, -1, 11, -1, -1, 15,
	-1, 13, 12, -1, 12, -1, 12, 12, 14, -1, -1, 4, -1, 8, 12, -1,
	13, 13, -1, 13, -1, 13, 12, -1, -1, 13, 9, -1, 5, -1, -1, 15,
	14, -1, -1, 10, -1, 6, 12, -1, 14, 14, 14, -1, 14, -1, -1, 15,
	-1, 13, 7, -1, 11, -1, -1, 15, 14, -1, -1, 15, -1, 15, 15, 15,
}
