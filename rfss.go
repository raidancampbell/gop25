package p25

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// idleDespawn is how long a monitored sibling site may go without a decoded
// TSBK before the supervisor releases its channelizer slot. Re-spawned on the
// next Active ADJ_STS. See the Phase 2 design (decision 2026-06-13).
const idleDespawn = 120 * time.Second

// pendingNACTimeout bounds how long a NAC-agnostic CC is given to decode its
// first NID before the supervisor gives up and despawns it.
const pendingNACTimeout = 30 * time.Second

// monitoredSite is one site whose CC the supervisor is decoding.
type monitoredSite struct {
	site   uint8
	ccFreq uint32
	sys    *System
	cc     CCHandle
	seed   bool // a configured [[trunk]]; never auto-despawned
	// despawn marks the site for teardown by the ticker. It is set (never
	// cleared) by onSiteDiscover on a Failed/out-of-window broadcast or by tick
	// on idle, and the site is removed from r.monitored only after the ticker
	// has actually torn its CC down. The site stays in r.monitored (ignored by
	// onSiteDiscover) until then so it neither re-spawns nor is torn down twice.
	despawn bool
}

// pendingSite is a discovered site whose NAC-agnostic CC is spawned but whose
// NAC has not yet been observed, so its System is not yet built.
type pendingSite struct {
	site   uint8
	ccFreq uint32
	cc     CCHandle
	since  time.Time
}

// RFSS supervises the set of per-site Systems for one (SysID, RFSS). Configured
// trunks are seeds; sibling sites advertised Active and in-window are spawned
// automatically up to maxSites, NAC-self-identified, and despawned when they go
// Failed, leave the window, or fall silent. The seed set and the discovered
// (monitored + pending) sets all count against maxSites, which bounds the total
// number of concurrent CC decoders for CPU.
type RFSS struct {
	host      Host
	maxSites  int
	siteNames map[uint8]string // optional site#→name (config [site_names]); fallback "S<n>"

	mu        sync.Mutex
	seeds     []*monitoredSite         // configured trunks; never despawned
	monitored map[uint8]*monitoredSite // discovered sites by site number
	pending   map[uint8]*pendingSite   // discovered, NAC self-ID in flight
}

func NewRFSS(host Host, maxSites int) *RFSS {
	return &RFSS{
		host:      host,
		maxSites:  maxSites,
		monitored: make(map[uint8]*monitoredSite),
		pending:   make(map[uint8]*pendingSite),
	}
}

// SetSiteNames installs an optional site#→name map used to label discovered
// sites (e.g. "Flat Top CC" instead of "S25 CC"). Call before Seed/Run. Seeds
// keep their configured [[trunk]] label; this only affects auto-discovered sites.
func (r *RFSS) SetSiteNames(m map[uint8]string) { r.siteNames = m }

// siteLabel returns the configured human name for a site, or the generic
// "S<n>" fallback. Safe on a nil map.
func (r *RFSS) siteLabel(site uint8) string {
	if name := r.siteNames[site]; name != "" {
		return name
	}
	return fmt.Sprintf("S%d", site)
}

// Seed registers a configured trunk as a permanent (never-despawned) site and
// starts it. The seed observes SiteDiscovery and feeds it to the supervisor.
func (r *RFSS) Seed(td SystemDef) {
	sys := NewSystem(td, r.host)
	sys.SetSiteObserver(r.onSiteDiscover)
	sys.Start()
	r.mu.Lock()
	r.seeds = append(r.seeds, &monitoredSite{ccFreq: td.ControlFreq, sys: sys, cc: sys.CC(), seed: true})
	r.mu.Unlock()
}

// countLocked returns the number of CC decoders held against the cap. Caller
// holds r.mu.
func (r *RFSS) countLocked() int { return len(r.seeds) + len(r.monitored) + len(r.pending) }

// onSiteDiscover is the edge-triggered entry point fed by every seed and
// discovered System's site observer. It is called ON THE CC DECODE-PUMP
// GOROUTINE, so it must never call host.DespawnCC (which joins that very
// goroutine — see tick). It only records intent under r.mu; the ticker performs
// teardown off the pump goroutine.
func (r *RFSS) onSiteDiscover(d SiteDiscovery) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// A seed re-advertising its own CC (CCFreq>0) is already permanently
	// monitored. Guard CCFreq!=0 so an unresolved-iden broadcast (CCFreq==0)
	// from any site doesn't spuriously match a seed.
	for _, s := range r.seeds {
		if d.CCFreq != 0 && s.ccFreq == d.CCFreq {
			return
		}
	}

	// Health updates / despawn marking for sites we already monitor.
	if ms, ok := r.monitored[d.Site]; ok {
		if ms.despawn {
			return // already being torn down by the ticker; ignore
		}
		if d.CCFreq != 0 {
			ms.ccFreq = d.CCFreq // don't clobber a known freq with an unresolved 0
		}
		// Only a resolved (non-zero) CC freq can be judged out-of-window;
		// CCFreq==0 means the iden isn't decoded yet, not that the site moved.
		if d.Failed || (d.CCFreq != 0 && !r.host.InWindow(d.CCFreq)) {
			ms.despawn = true // tick tears it down off the pump goroutine
		}
		return
	}
	if _, ok := r.pending[d.Site]; ok {
		return // already spawning; NAC self-ID in flight
	}

	// Eligibility for a new spawn (R3): Active, not Failed, resolved CC freq,
	// in window, and under the concurrency cap.
	if !d.Active || d.Failed || d.CCFreq == 0 || !r.host.InWindow(d.CCFreq) {
		return
	}
	if r.countLocked() >= r.maxSites {
		r.host.Log().Debug("RFSS site cap reached; not spawning",
			"site", d.Site, "cap", r.maxSites)
		return
	}

	// Spawn NAC-agnostic; bindPending builds the System once the NAC is known.
	label := r.siteLabel(d.Site)
	cc := r.host.SpawnCC(d.CCFreq, 0, label+" CC", 12500, false)
	if cc == nil {
		return
	}
	r.pending[d.Site] = &pendingSite{site: d.Site, ccFreq: d.CCFreq, cc: cc, since: time.Now()}
	r.host.Log().Info("RFSS spawning sibling site CC (awaiting NAC)",
		"site", d.Site, "cc_freq", d.CCFreq)
}

// bindPending promotes pending sites whose NAC has been observed into full
// monitored Systems, and times out those that never decode a NID. Called
// periodically by the supervisor ticker (and directly in tests).
//
// StartWithCC is invoked while holding r.mu; it wires the tracker and spawns
// warm voice channels via the host but never re-enters onSiteDiscover
// synchronously (site broadcasts arrive later on the CC's own goroutine), so
// there is no self-deadlock. The NAC-timeout teardown, however, is run AFTER
// releasing r.mu — DespawnCC joins the CC's decode-pump goroutine, so calling
// it under r.mu risks deadlock (see tick).
func (r *RFSS) bindPending(now time.Time) {
	r.mu.Lock()
	var dead []CCHandle
	for site, p := range r.pending {
		if nac := p.cc.ObservedNAC(); nac != 0 {
			td := SystemDef{ControlFreq: p.ccFreq, NAC: nac, Label: r.siteLabel(site)}
			sys := NewSystem(td, r.host)
			sys.SetSiteObserver(r.onSiteDiscover)
			sys.StartWithCC(p.cc)
			r.monitored[site] = &monitoredSite{site: site, ccFreq: p.ccFreq, sys: sys, cc: p.cc}
			delete(r.pending, site)
			r.host.Log().Info("RFSS bound sibling site to observed NAC",
				"site", site, "nac", nac)
			continue
		}
		if now.Sub(p.since) > pendingNACTimeout {
			dead = append(dead, p.cc)
			delete(r.pending, site)
			r.host.Log().Warn("RFSS pending site never decoded a NAC; despawned",
				"site", site)
		}
	}
	r.mu.Unlock()
	// A pending CC has no tracker, so its pump never re-enters onSiteDiscover;
	// still, despawn off-lock for uniformity with tick's monitored teardown.
	for _, cc := range dead {
		r.host.DespawnCC(cc)
	}
}

// Systems returns the Systems the supervisor currently owns: the seeds plus any
// discovered sibling sites bound so far. A host UI takes a startup snapshot for
// its trunk panels; the set changes over time as sites spawn/despawn (a
// live-updating panel list is a follow-on).
func (r *RFSS) Systems() []*System {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*System, 0, len(r.seeds)+len(r.monitored))
	for _, s := range r.seeds {
		if s.sys != nil {
			out = append(out, s.sys)
		}
	}
	// Discovered sites live in a map, whose random iteration order made a host
	// UI panel reshuffle on every refresh. Emit them in a stable order — ascending
	// site number — after the config-ordered seeds.
	mon := make([]*monitoredSite, 0, len(r.monitored))
	for _, ms := range r.monitored {
		if ms.sys != nil {
			mon = append(mon, ms)
		}
	}
	sort.Slice(mon, func(i, j int) bool { return mon[i].site < mon[j].site })
	for _, ms := range mon {
		out = append(out, ms.sys)
	}
	return out
}

// monitoring reports whether the supervisor currently decodes the given
// discovered site (seeds are tracked separately and are not reported here).
func (r *RFSS) monitoring(site uint8) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.monitored[site]
	return ok
}

// tick performs one supervisor maintenance pass: bind pending sites (NAC
// self-ID) and despawn monitored sites that are silent beyond idleDespawn or
// were flagged for despawn by onSiteDiscover (Failed/out-of-window). Seeds are
// not in r.monitored, so they are never despawned. Separated from Run for
// deterministic testing.
//
// CRITICAL: host.DespawnCC synchronously joins the target CC's decode-pump
// goroutine (RemoveChannel -> OnClose -> pump.Close -> wg.Wait). That pump
// goroutine re-enters the supervisor via onSiteDiscover (which takes r.mu).
// So DespawnCC must run (a) OUTSIDE r.mu and (b) on this ticker goroutine, never
// on a pump goroutine. We therefore flag+snapshot under the lock, DespawnCC
// unlocked, then drop the entries under the lock. Flagged sites stay in
// r.monitored during teardown so onSiteDiscover ignores them (no re-spawn).
func (r *RFSS) tick(now time.Time) {
	r.bindPending(now)

	r.mu.Lock()
	var dead []*monitoredSite
	for _, ms := range r.monitored {
		if ms.cc == nil {
			continue
		}
		if !ms.despawn {
			last := ms.cc.LastActivity()
			if last.IsZero() || now.Sub(last) <= idleDespawn {
				continue // never produced a TSBK yet, or still active: keep
			}
			ms.despawn = true
		}
		dead = append(dead, ms)
	}
	r.mu.Unlock()

	for _, ms := range dead {
		r.host.DespawnCC(ms.cc) // off-lock, on the ticker goroutine
	}

	if len(dead) > 0 {
		r.mu.Lock()
		for _, ms := range dead {
			delete(r.monitored, ms.site)
			r.host.Log().Info("RFSS despawned sibling site", "site", ms.site)
		}
		r.mu.Unlock()
	}
}

// Run drives the supervisor maintenance loop until ctx is cancelled.
func (r *RFSS) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.tick(now)
		}
	}
}
