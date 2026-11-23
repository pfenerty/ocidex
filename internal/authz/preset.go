package authz

// Preset is a named capability set for an agent key (ADR-0058 A3). Picking
// from ten capabilities is how keys end up over-granted; a preset names the
// job instead. Presets are compile-time, like roles, so the conformance
// harness and the tests below see every one.
type Preset struct {
	Name        string
	Title       string
	Description string
	// Capabilities is the key's ceiling.
	Capabilities []Capability
	// ApprovalRequired is the subset a person must approve on every request.
	ApprovalRequired []Capability
}

var presets = []Preset{
	{
		Name:         "analyst",
		Title:        "Read-only analyst",
		Description:  "Reads everything in its namespaces, private data included. Changes nothing.",
		Capabilities: []Capability{CapReadPrivate},
	},
	{
		Name:  "remediation",
		Title: "Remediation assistant",
		Description: "Reads everything in its namespaces and can manage its holder's own watchlist, " +
			"which needs no capability. Starts no scans.",
		Capabilities: []Capability{CapReadPrivate},
	},
	{
		Name:  "coverage",
		Title: "Coverage operator",
		Description: "Reads everything in its namespaces and can ask to scan registries and the images " +
			"clusters run with no SBOM. Each scan waits for a person's approval.",
		Capabilities:     []Capability{CapReadPrivate, CapTriggerScan},
		ApprovalRequired: []Capability{CapTriggerScan},
	},
}

// Presets returns every agent key preset, in display order. Fresh slice.
func Presets() []Preset {
	return append([]Preset(nil), presets...)
}

// PresetByName returns the preset called name.
func PresetByName(name string) (Preset, bool) {
	for _, p := range presets {
		if p.Name == name {
			return p, true
		}
	}
	return Preset{}, false
}

// AgentMayHold reports whether an agent key may carry c at all (ADR-0058 A7).
// Managing who belongs to a namespace and administering the installation are
// decisions about people and the system, never delegated to a program.
func AgentMayHold(c Capability) bool {
	return c != CapManageMember && c != CapInstallationAdmin && c != CapDeleteNamespace
}
