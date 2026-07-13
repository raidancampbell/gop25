package p25

import (
	"reflect"
	"testing"
	"time"
)

// Systems() must return a deterministic order — the seed first (config order),
// then discovered sites ascending by SITE NUMBER — so a host UI panel doesn't
// reshuffle every refresh from the underlying map's random iteration order.
func TestRFSS_SystemsOrderStableBySite(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	r := NewRFSS(host, 8)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "Seed"})

	// Discover three sites OUT of site order, with NACs whose order differs from
	// the site order — so the assertion distinguishes site-sort from both
	// insertion order and NAC order.
	host.nextCCNAC = 0x111
	r.onSiteDiscover(SiteDiscovery{Site: 27, CCFreq: 452_237_500, Active: true})
	host.nextCCNAC = 0x222
	r.onSiteDiscover(SiteDiscovery{Site: 25, CCFreq: 453_787_500, Active: true})
	host.nextCCNAC = 0x333
	r.onSiteDiscover(SiteDiscovery{Site: 34, CCFreq: 460_362_500, Active: true})
	r.bindPending(time.Now())

	nacs := func() []uint16 {
		var o []uint16
		for _, s := range r.Systems() {
			o = append(o, s.NAC())
		}
		return o
	}
	// seed (0x171), then sites 25, 27, 34 -> NACs 0x222, 0x111, 0x333
	want := []uint16{0x171, 0x222, 0x111, 0x333}
	if got := nacs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Systems order = %#x, want %#x", got, want)
	}
	for i := 0; i < 30; i++ {
		if got := nacs(); !reflect.DeepEqual(got, want) {
			t.Fatalf("Systems order not stable across calls: %#x vs %#x", got, want)
		}
	}
}

func TestRFSS_SpawnsActiveInWindowSiteUnderCap(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(f uint32) bool { return f >= 447_000_000 && f <= 467_000_000 }
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})

	// Active in-window neighbor → spawn. The fake CC reports its NAC at once.
	host.nextCCNAC = 0x176
	r.onSiteDiscover(SiteDiscovery{SysID: 368, RFSS: 2, Site: 26, CCFreq: 460_862_500, Active: true})
	r.bindPending(time.Now()) // drain NAC self-ID (the ticker does this live)

	if !r.monitoring(26) {
		t.Errorf("site 26 not monitored after Active in-window discovery")
	}
	if host.ccSpawns != 2 { // seed + discovered
		t.Errorf("ccSpawns = %d, want 2", host.ccSpawns)
	}
}

func TestRFSS_IgnoresInactiveOutOfWindowDuplicate(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(f uint32) bool { return f >= 447_000_000 && f <= 467_000_000 }
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})

	r.onSiteDiscover(SiteDiscovery{Site: 99, CCFreq: 460_862_500, Active: false}) // inactive
	r.onSiteDiscover(SiteDiscovery{Site: 98, CCFreq: 470_000_000, Active: true})  // out of window
	r.onSiteDiscover(SiteDiscovery{Site: 97, CCFreq: 0, Active: true})            // unresolved iden
	r.bindPending(time.Now())
	if r.monitoring(99) || r.monitoring(98) || r.monitoring(97) {
		t.Errorf("supervisor spawned an ineligible site")
	}
	if host.ccSpawns != 1 { // only the seed
		t.Errorf("ccSpawns = %d, want 1 (no ineligible spawns)", host.ccSpawns)
	}
}

func TestRFSS_HonorsCap(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	host.nextCCNAC = 0x171
	r := NewRFSS(host, 1) // cap 1: only the seed fits
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Active: true})
	r.bindPending(time.Now())
	if r.monitoring(26) {
		t.Errorf("cap exceeded: site 26 spawned with cap=1 and seed present")
	}
}

func TestRFSS_IgnoresSeedOwnSiteBroadcast(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	// The seed re-advertises its own CC (Self=true) — must not spawn a duplicate.
	r.onSiteDiscover(SiteDiscovery{Site: 41, CCFreq: 460_412_500, Active: true, Self: true})
	r.bindPending(time.Now())
	if host.ccSpawns != 1 {
		t.Errorf("ccSpawns = %d, want 1 (seed's own CC must not respawn)", host.ccSpawns)
	}
}

func TestRFSS_DespawnsSilentSite(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	host.nextCCNAC = 0x176
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Active: true})
	r.bindPending(time.Now())
	if !r.monitoring(26) {
		t.Fatal("precondition: site 26 should be monitored")
	}
	// Its CC reports an old LastActivity → silent beyond idleDespawn.
	host.setLastActivityFreq(460_862_500, time.Now().Add(-idleDespawn-time.Second))
	r.tick(time.Now())
	if r.monitoring(26) {
		t.Errorf("silent site 26 was not despawned")
	}
	if len(host.despawned) != 1 || host.despawned[0] != 460_862_500 {
		t.Errorf("despawned = %v, want [460862500]", host.despawned)
	}
}

func TestRFSS_KeepsSeedDespiteSilence(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	host.setLastActivityFreq(460_412_500, time.Now().Add(-2*idleDespawn))
	r.tick(time.Now())
	// The seed is the bootstrap — it must survive silence.
	if len(host.despawned) != 0 {
		t.Errorf("seed was despawned on silence: %v", host.despawned)
	}
}

func TestRFSS_DespawnsFailedSite(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	host.nextCCNAC = 0x176
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Active: true})
	r.bindPending(time.Now())
	if !r.monitoring(26) {
		t.Fatal("precondition: site 26 should be monitored")
	}
	// A later Failed broadcast only FLAGS the site (onSiteDiscover runs on the
	// CC pump goroutine and must not join it via DespawnCC). The ticker tears
	// it down off the pump goroutine.
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Failed: true})
	r.tick(time.Now())
	if r.monitoring(26) {
		t.Errorf("Failed site 26 was not despawned after tick")
	}
	if len(host.despawned) != 1 || host.despawned[0] != 460_862_500 {
		t.Errorf("despawned = %v, want [460862500]", host.despawned)
	}
}

// TestRFSS_UnresolvedIdenDoesNotDespawn guards the deterministic self-despawn
// bug: a bound site whose own RFSS_STS arrives before its iden table decodes
// resolves CCFreq=0. That must NOT be read as "out of window" (which would tear
// down a healthy site — and, before the fix, deadlock on its own pump).
func TestRFSS_UnresolvedIdenDoesNotDespawn(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(f uint32) bool { return f >= 447_000_000 && f <= 467_000_000 }
	host.nextCCNAC = 0x176
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Active: true})
	r.bindPending(time.Now())
	if !r.monitoring(26) {
		t.Fatal("precondition: site 26 should be monitored")
	}
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 0, Self: true}) // iden not yet known
	r.tick(time.Now())
	if !r.monitoring(26) {
		t.Errorf("site 26 despawned on an unresolved-iden (CCFreq=0) broadcast")
	}
	if len(host.despawned) != 0 {
		t.Errorf("unexpected despawn on CCFreq=0: %v", host.despawned)
	}
}

// TestRFSS_DespawnDoesNotDeadlockWithSiteObserver models the real hazard: the
// host's DespawnCC joins the CC's decode-pump goroutine, which re-enters the
// supervisor via onSiteDiscover under r.mu. If the supervisor despawned while
// holding r.mu (or on the pump path), this deadlocks. The despawnHook simulates
// that re-entry; the test must complete promptly.
func TestRFSS_DespawnDoesNotDeadlockWithSiteObserver(t *testing.T) {
	host := newFakeHost()
	host.inWin = func(uint32) bool { return true }
	host.nextCCNAC = 0x176
	r := NewRFSS(host, 3)
	r.Seed(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "S41"})
	r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500, Active: true})
	r.bindPending(time.Now())
	if !r.monitoring(26) {
		t.Fatal("precondition: site 26 should be monitored")
	}
	// During teardown the pump fires one more onSiteDiscover; it must be able to
	// take r.mu, i.e. DespawnCC must not be holding it.
	host.despawnHook = func(CCHandle) {
		r.onSiteDiscover(SiteDiscovery{Site: 26, CCFreq: 460_862_500})
	}
	host.setLastActivityFreq(460_862_500, time.Now().Add(-idleDespawn-time.Second))

	done := make(chan struct{})
	go func() { r.tick(time.Now()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tick deadlocked: DespawnCC ran under r.mu while a pump re-entered onSiteDiscover")
	}
	if r.monitoring(26) {
		t.Errorf("silent site 26 was not despawned")
	}
}
