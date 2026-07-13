package p25

// extractBits extracts n bits from a dibit slice starting at bit offset.
// Dibits are packed MSB-first: dibit 0 contributes bits 0-1, dibit 1 bits 2-3, etc.
func extractBits(dibits []Dibit, bitOffset, nBits int) uint32 {
	var val uint32
	for i := 0; i < nBits; i++ {
		bi := bitOffset + i
		di := bi / 2
		bitInDibit := 1 - (bi % 2) // MSB first within dibit
		if di < len(dibits) && (dibits[di]>>uint(bitInDibit))&1 != 0 {
			val |= 1 << uint(nBits-1-i)
		}
	}
	return val
}

// dibitsToBits converts a dibit slice to a bit slice (MSB first per dibit).
func dibitsToBits(dibits []Dibit) []uint8 {
	out := make([]uint8, len(dibits)*2)
	for i, d := range dibits {
		out[i*2] = uint8((d >> 1) & 1)
		out[i*2+1] = uint8(d & 1)
	}
	return out
}

// bitsToUint32 packs up to 32 bits into a uint32, MSB first.
func bitsToUint32(b []uint8) uint32 {
	var v uint32
	for _, bit := range b {
		v = (v << 1) | uint32(bit&1)
	}
	return v
}

// bitsToUint16 packs up to 16 bits into a uint16, MSB first.
func bitsToUint16(b []uint8) uint16 {
	var v uint16
	for _, bit := range b {
		v = (v << 1) | uint16(bit&1)
	}
	return v
}

// --- Hamming(10,6,3) — TIA-102.BAAA §5.4 -----------------------------------
//
// Each LDU LC/ES fragment is encoded as 24 ten-bit Hamming(10,6,3) codewords:
// 6 data bits (one RS hexbit) + 4 parity bits, single-error-correcting.
// Tables match op25's hmg1063EncTbl/hmg1063DecTbl (op25_hamming.h:187-198).

var hmg1063EncTbl = [64]uint8{
	0, 12, 3, 15, 7, 11, 4, 8, 11, 7, 8, 4, 12, 0, 15, 3,
	13, 1, 14, 2, 10, 6, 9, 5, 6, 10, 5, 9, 1, 13, 2, 14,
	14, 2, 13, 1, 9, 5, 10, 6, 5, 9, 6, 10, 2, 14, 1, 13,
	3, 15, 0, 12, 4, 8, 7, 11, 8, 4, 11, 7, 15, 3, 12, 0,
}

var hmg1063DecTbl = [16]uint8{
	0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 8, 1, 16, 32, 0,
}

// hamming1063Decode corrects up to one bit error in the 6-bit data field of
// a Hamming(10,6,3) codeword and returns the corrected 6-bit hexbit.
func hamming1063Decode(data6, parity4 uint8) uint8 {
	return (data6 & 0x3F) ^ hmg1063DecTbl[hmg1063EncTbl[data6&0x3F]^(parity4&0x0F)]
}

// hamming1063Encode returns the 4-bit parity for a 6-bit data hexbit.
func hamming1063Encode(data6 uint8) uint8 {
	return hmg1063EncTbl[data6&0x3F]
}

// lduLCBitPositions are the full-frame bit indices of the 240 LC/ES bits in
// an LDU (24 codewords × 10 bits each), copied from op25's
// imbe_ldu_ls_data_bits (op25_imbe_frame.h:89). Bit index = full-frame bit,
// where bit 0 is the first bit of the sync word.
var lduLCBitPositions = [240]uint16{
	410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421,
	422, 423, 424, 425, 426, 427, 428, 429, 432, 433, 434, 435,
	436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447,
	448, 449, 450, 451, 600, 601, 602, 603, 604, 605, 606, 607,
	608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619,
	620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631,
	632, 633, 634, 635, 636, 637, 638, 639, 788, 789, 792, 793,
	794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805,
	806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817,
	818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829,
	978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989,
	990, 991, 992, 993, 994, 995, 996, 997, 998, 999, 1000, 1001,
	1002, 1003, 1004, 1005, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015,
	1016, 1017, 1018, 1019, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175,
	1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183, 1184, 1185, 1186, 1187,
	1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199,
	1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1356, 1357, 1358, 1359,
	1360, 1361, 1362, 1363, 1364, 1365, 1368, 1369, 1370, 1371, 1372, 1373,
	1374, 1375, 1376, 1377, 1378, 1379, 1380, 1381, 1382, 1383, 1384, 1385,
	1386, 1387, 1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1396, 1397,
}

// extractLDUHexbits collects the 24 LC/ES hexbits from an LDU payload by
// reading 24 ten-bit Hamming(10,6,3) codewords at the positions given by
// lduLCBitPositions. The op25 table indexes full-frame bits; payload bit p
// corresponds to full-frame bit p + 2*(syncLen+nidSpan) = p + 114.
func extractLDUHexbits(payload []Dibit) (hb [24]uint8, ok bool) {
	const fullFrameOffset = 2 * (syncLen + nidSpan) // 114 bits
	for i := range 24 {
		var cw uint16
		for j := range 10 {
			fb := int(lduLCBitPositions[i*10+j])
			pb := fb - fullFrameOffset
			di := pb / 2
			if di < 0 || di >= len(payload) {
				return hb, false
			}
			bit := uint16((payload[di] >> uint(1-pb%2)) & 1)
			cw = (cw << 1) | bit
		}
		hb[i] = hamming1063Decode(uint8(cw>>4), uint8(cw&0x0F))
	}
	return hb, true
}

