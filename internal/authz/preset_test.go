package authz

import (
	"slices"
	"testing"
)

func TestPresetsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets() {
		if p.Name == "" || seen[p.Name] {
			t.Errorf("preset %q: empty or duplicate name", p.Name)
		}
		seen[p.Name] = true
		if len(p.Capabilities) == 0 {
			t.Errorf("preset %q has no capabilities", p.Name)
		}
		for _, c := range p.Capabilities {
			if !c.Valid() {
				t.Errorf("preset %q: unknown capability %q", p.Name, c)
			}
			if !AgentMayHold(c) {
				t.Errorf("preset %q carries %q, which no agent key may hold", p.Name, c)
			}
		}
		for _, c := range p.ApprovalRequired {
			if !slices.Contains(p.Capabilities, c) || !c.Mutating() {
				t.Errorf("preset %q: approval-required %q must be a mutating capability it carries", p.Name, c)
			}
		}
	}
	if _, ok := PresetByName("coverage"); !ok {
		t.Error("coverage preset missing")
	}
}
