package p25

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// KV is one labeled field in a dissected layer.
type KV struct{ Key, Val string }

// Layer is one protocol level of a dissected datagram. Undecoded holds bytes
// this layer could not interpret (nil on a clean decode).
type Layer struct {
	Name      string
	Fields    []KV
	Undecoded []byte
}

// Dissection is the ordered protocol stack of one IP datagram, built for a
// host UI's detail pane. It reuses the same parsers the live decode path uses.
type Dissection struct {
	Layers []Layer
}

// Dissect walks one raw IP datagram into labeled protocol layers. It is total:
// any parse failure degrades to an Undecoded byte range, never a panic or a
// non-total nil. A non-IPv4 buffer yields a single "raw" layer.
func Dissect(raw []byte) *Dissection {
	d := &Dissection{}
	ip := parseIPv4(raw)
	if ip == nil {
		d.Layers = append(d.Layers, Layer{Name: "raw", Undecoded: raw})
		return d
	}
	ipLayer := Layer{Name: "IPv4", Fields: []KV{
		{"src", net.IP(ip.Src[:]).String()},
		{"dst", net.IP(ip.Dst[:]).String()},
		{"proto", ipProtoName(ip.Protocol)},
		{"len", fmt.Sprintf("%d", ip.TotalLen)},
	}}

	switch ip.Protocol {
	case 17: // UDP
		d.Layers = append(d.Layers, ipLayer)
		d.dissectUDP(ip.Payload)
	case 1: // ICMP
		d.Layers = append(d.Layers, ipLayer)
		d.dissectICMP(ip.Payload)
	default:
		ipLayer.Undecoded = ip.Payload
		d.Layers = append(d.Layers, ipLayer)
	}
	return d
}

func (d *Dissection) dissectUDP(payload []byte) {
	udp := parseUDP(payload)
	if udp == nil {
		d.Layers = append(d.Layers, Layer{Name: "UDP", Undecoded: payload})
		return
	}
	d.Layers = append(d.Layers, Layer{Name: "UDP", Fields: []KV{
		{"src", fmt.Sprintf("%d", udp.SrcPort)},
		{"dst", fmt.Sprintf("%d", udp.DstPort)},
		{"len", fmt.Sprintf("%d", udp.Length)},
	}})
	switch udp.DstPort {
	case 4001:
		d.dissectLRRP(udp.Payload)
	case 4005:
		d.dissectARS(udp.Payload)
	default:
		// Annotate the UDP layer with the leftover application bytes.
		d.Layers[len(d.Layers)-1].Undecoded = udp.Payload
	}
}

func (d *Dissection) dissectLRRP(payload []byte) {
	l := parseLRRP(payload)
	if l == nil {
		d.Layers = append(d.Layers, Layer{Name: "LRRP", Undecoded: payload})
		return
	}
	layer := Layer{Name: "LRRP", Undecoded: l.Trailing}
	layer.Fields = append(layer.Fields, KV{"type", fmt.Sprintf("0x%02x", l.PacketType)})
	for _, tok := range l.Tokens {
		name, val := tok.Describe()
		layer.Fields = append(layer.Fields, KV{name, val})
	}
	d.Layers = append(d.Layers, layer)
}

func (d *Dissection) dissectARS(payload []byte) {
	a := parseARS(payload)
	if a == nil {
		d.Layers = append(d.Layers, Layer{Name: "ARS", Undecoded: payload})
		return
	}
	layer := Layer{Name: "ARS"}
	layer.Fields = append(layer.Fields, KV{"type", a.PDUTypeName()})
	flags := ""
	if a.HasExtension {
		flags += "ext "
	}
	if a.Acknowledge {
		flags += "ack "
	}
	if a.Priority {
		flags += "prio "
	}
	if a.Control {
		flags += "ctrl "
	}
	if flags != "" {
		layer.Fields = append(layer.Fields, KV{"flags", strings.TrimSpace(flags)})
	}
	if a.HasTimestamp {
		layer.Fields = append(layer.Fields,
			KV{"timestamp", time.Unix(int64(a.Timestamp), 0).UTC().Format("2006-01-02 15:04:05Z")})
	}
	d.Layers = append(d.Layers, layer)
}

func (d *Dissection) dissectICMP(payload []byte) {
	c := parseICMP(payload)
	if c == nil {
		d.Layers = append(d.Layers, Layer{Name: "ICMP", Undecoded: payload})
		return
	}
	layer := Layer{Name: "ICMP"}
	name := c.TypeName
	if c.CodeName != "" {
		name = fmt.Sprintf("%s/%s", c.TypeName, c.CodeName)
	}
	layer.Fields = append(layer.Fields, KV{"type", name})
	if c.HasOrigPort {
		layer.Fields = append(layer.Fields, KV{"orig-dst-port", fmt.Sprintf("%d", c.OrigDstPort)})
	}
	d.Layers = append(d.Layers, layer)
}

func ipProtoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 17:
		return "UDP"
	}
	return fmt.Sprintf("IP/%d", p)
}
