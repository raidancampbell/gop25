package p25

// SystemDef is the minimal trunked-system definition the P25 decoder needs.
// The host application maps its own richer config type onto this at call time,
// so the P25 stack does not depend on any host config package.
type SystemDef struct {
	ControlFreq  uint32  // control channel center frequency, Hz
	NAC          uint16  // network access code
	Label        string  // human label for logs/UI
	Bandwidth    float64 // channel bandwidth hint passed to the host when spawning the CC (0 = host default)
	ContinuousIQ bool    // request continuous-IQ capture on spawned pipelines

	// AllowTGIDs / DenyTGIDs are an optional per-system talkgroup filter applied
	// to voice grants. When two sites simulcast the same talkgroups, this lets
	// one site "own" a TG so the receiver doesn't follow grants for it on the
	// weaker site. Semantics (evaluated in this order):
	//   - DenyTGIDs takes precedence: a TGID listed here is never followed.
	//   - If AllowTGIDs is non-empty it is a whitelist: only listed TGIDs are
	//     followed. An empty AllowTGIDs means "allow all" (subject to DenyTGIDs).
	// The control channel and data-channel discovery are unaffected; only voice
	// pipeline spawn/grant-hold is gated.
	AllowTGIDs []uint16
	DenyTGIDs  []uint16
}
