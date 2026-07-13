package phase2

import (
	"testing"

	"github.com/raidancampbell/gop25"
)

// magicDibits unpacks SyncMagic (40 bits, MSB-first) into 20 dibits.
func magicDibits() []p25.Dibit {
	out := make([]p25.Dibit, SyncDibits)
	for i := 0; i < SyncDibits; i++ {
		shift := uint(38 - 2*i)
		out[i] = p25.Dibit((SyncMagic >> shift) & 0x3)
	}
	return out
}

func TestFramer_FindsSyncAndCollectsBurst(t *testing.T) {
	// Prepend 50 random dibits, then sync, then a 180-dibit payload
	// (sync is the first 20 dibits of the burst).
	var stream []p25.Dibit
	for i := 0; i < 50; i++ {
		stream = append(stream, p25.Dibit(i%4))
	}
	sync := magicDibits()
	payload := make([]p25.Dibit, BurstDibits)
	copy(payload, sync) // burst begins with sync
	for i := SyncDibits; i < BurstDibits; i++ {
		payload[i] = p25.Dibit((i * 3) % 4)
	}
	stream = append(stream, payload...)

	f := NewFramer()
	bursts := f.Feed(stream)
	if len(bursts) != 1 {
		t.Fatalf("expected 1 burst, got %d", len(bursts))
	}
	for i := 0; i < BurstDibits; i++ {
		if bursts[0].Dibits[i] != payload[i] {
			t.Errorf("burst dibit %d = %d, want %d", i, bursts[0].Dibits[i], payload[i])
		}
	}
}

func TestFramer_ToleratesUpTo4BitErrors(t *testing.T) {
	sync := magicDibits()
	// Flip the bottom bit of the first two dibits: that's 2 bit errors.
	sync[0] ^= 1
	sync[1] ^= 1
	var stream []p25.Dibit
	stream = append(stream, sync...)
	for i := SyncDibits; i < BurstDibits; i++ {
		stream = append(stream, p25.Dibit(i%4))
	}
	f := NewFramer()
	bursts := f.Feed(stream)
	if len(bursts) != 1 {
		t.Fatalf("sync with 2 bit errors should be accepted; got %d bursts", len(bursts))
	}
}

func TestFramer_RejectsTooManyErrors(t *testing.T) {
	sync := magicDibits()
	// Replace first 5 dibits → 10 bit errors >> threshold of 4.
	for i := 0; i < 5; i++ {
		sync[i] = (sync[i] + 2) & 3
	}
	var stream []p25.Dibit
	stream = append(stream, sync...)
	for i := SyncDibits; i < BurstDibits; i++ {
		stream = append(stream, p25.Dibit(i%4))
	}
	f := NewFramer()
	if bursts := f.Feed(stream); len(bursts) != 0 {
		t.Errorf("sync with 10 bit errors should be rejected; got %d bursts", len(bursts))
	}
}
