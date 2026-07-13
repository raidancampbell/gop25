package mbe

import "testing"

func TestGeneratedTableShapes(t *testing.T) {
	if len(ws) != 321 {
		t.Fatalf("len(ws) = %d, want 321", len(ws))
	}
	if len(quantstep) != 11 {
		t.Fatalf("len(quantstep) = %d, want 11", len(quantstep))
	}
	if len(ambeW0Table) != 120 {
		t.Fatalf("len(ambeW0Table) = %d, want 120", len(ambeW0Table))
	}
}
