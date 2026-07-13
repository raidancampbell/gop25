package p25

import "testing"

func TestNewSystem_AcceptsSystemDef(t *testing.T) {
	h := newFakeHost() // existing test helper
	s := NewSystem(SystemDef{ControlFreq: 460_412_500, NAC: 0x171, Label: "T"}, h)
	if s.NAC() != 0x171 {
		t.Fatalf("NAC = %#x, want 0x171", s.NAC())
	}
	if s.Label() != "T" {
		t.Fatalf("Label = %q, want T", s.Label())
	}
}
