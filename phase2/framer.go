package phase2

import (
	"math/bits"

	"github.com/raidancampbell/gop25"
)

// Framer scans a Phase 2 dibit stream for the SyncMagic pattern and
// accumulates 180-dibit (30 ms) bursts. After initial sync, it tracks
// consecutive bursts by counting dibits (like op25's d_in_sync mechanism),
// collecting both S-ISCH and I-ISCH bursts.
type Framer struct {
	// accum holds the most recent 40 bits as a uint64 (low bits = most recent).
	accum uint64

	// state machine
	collecting bool
	tracking   bool // true after first sync; stay in collecting mode between bursts
	burst      [BurstDibits]p25.Dibit
	burstIdx   int
}

// NewFramer returns a Framer in the "searching" state.
func NewFramer() *Framer { return &Framer{} }

// Feed consumes dibits and returns any completed bursts.
func (f *Framer) Feed(dibits []p25.Dibit) []Burst {
	var out []Burst
	for _, d := range dibits {
		f.accum = ((f.accum << 2) | uint64(d&3)) & SyncMask

		if f.collecting {
			f.burst[f.burstIdx] = d
			f.burstIdx++
			if f.burstIdx == BurstDibits {
				out = append(out, Burst{Dibits: f.burst})
				if f.tracking {
					// Stay in collecting mode for the next burst.
					f.burstIdx = 0
				} else {
					f.collecting = false
					f.burstIdx = 0
				}
			}
			continue
		}

		// Searching — does the trailing 40 bits match sync within threshold?
		if syncErrors(f.accum) <= SyncErrorThreshold {
			f.collecting = true
			f.tracking = true
			f.burstIdx = 0
			// The 20 dibits of sync are the first 20 dibits of the burst.
			for i := 0; i < SyncDibits; i++ {
				shift := uint(38 - 2*i)
				f.burst[i] = p25.Dibit((f.accum >> shift) & 0x3)
			}
			f.burstIdx = SyncDibits
		}
	}
	return out
}

// syncErrors returns the bit-distance between candidate and SyncMagic.
func syncErrors(candidate uint64) int {
	return bits.OnesCount64((candidate ^ SyncMagic) & SyncMask)
}
