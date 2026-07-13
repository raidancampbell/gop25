package p25

// IPv4Data is the subset of an IPv4 header we need to route SN-DATA payloads
// to UDP (and through to LRRP). Header options are not parsed; the checksum is
// not verified - SN-DATA already CRC-32s the user payload it carries.
type IPv4Data struct {
	Version   uint8
	HeaderLen uint16 // header length in bytes (IHL * 4)
	TotalLen  uint16 // total packet length in bytes
	Protocol  uint8  // 17 = UDP, 1 = ICMP, etc.
	Src       [4]byte
	Dst       [4]byte
	// Payload is the bytes following the IPv4 header, sliced from the input
	// buffer. Caller owns the lifetime of the underlying buffer.
	Payload []byte
}

// parseIPv4 returns nil for any packet whose Version, IHL, TotalLen, or buffer
// length contradicts itself. Reference: sdrtrunk IPV4Header.java; RFC 791.
func parseIPv4(buf []byte) *IPv4Data {
	if len(buf) < 20 {
		return nil
	}
	version := (buf[0] >> 4) & 0x0f
	if version != 4 {
		return nil
	}
	ihl := buf[0] & 0x0f
	headerLen := uint16(ihl) * 4
	if headerLen < 20 || int(headerLen) > len(buf) {
		return nil
	}
	totalLen := uint16(buf[2])<<8 | uint16(buf[3])
	if totalLen < headerLen || int(totalLen) > len(buf) {
		return nil
	}
	ip := &IPv4Data{
		Version:   version,
		HeaderLen: headerLen,
		TotalLen:  totalLen,
		Protocol:  buf[9],
	}
	copy(ip.Src[:], buf[12:16])
	copy(ip.Dst[:], buf[16:20])
	ip.Payload = buf[headerLen:totalLen]
	return ip
}
