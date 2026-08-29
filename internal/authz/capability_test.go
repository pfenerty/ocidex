package authz

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryRoleDeclaresEveryCapability is the guard the capability model is
// built around. roleCaps names every capability for every role explicitly,
// including the denials, so that adding a Capability constant and forgetting a
// role fails here instead of shipping as an implicit deny nobody reviewed —
// or, when the missing cell is on the permissive side of a later refactor, as
// an implicit grant nobody reviewed.
//
// It checks both directions. A missing cell is an undecided capability; an
// extra cell is a capability that was renamed or deleted in the constant block
// and left behind in the table, where it reads as a live rule and is not one.
func TestEveryRoleDeclaresEveryCapability(t *testing.T) {
	if len(roleCaps) != len(allRoles) {
		t.Errorf("roleCaps has %d roles, allRoles has %d", len(roleCaps), len(allRoles))
	}

	known := make(map[Capability]bool, len(allCapabilities))
	for _, c := range allCapabilities {
		known[c] = true
	}

	for _, r := range allRoles {
		caps, ok := roleCaps[r]
		if !ok {
			t.Errorf("role %q has no roleCaps entry", r)
			continue
		}
		for _, c := range allCapabilities {
			if _, declared := caps[c]; !declared {
				t.Errorf("role %q does not declare capability %q: "+
					"add an explicit true or false, an omission is not a decision", r, c)
			}
		}
		for c := range caps {
			if !known[c] {
				t.Errorf("role %q declares unknown capability %q", r, c)
			}
		}
	}
}

// TestCapabilityMatrix pins the table itself. TestEveryRoleDeclaresEveryCapability
// proves every cell was filled in; this one proves they were filled in with the
// answers the epic decided on, written out a second time so that flipping a
// cell in roleCaps has to be a deliberate two-place edit rather than a typo.
//
// The two rows worth reading are security and developer. Security may
// trigger_scan but not ingest — confirming a fix must not require the right to
// publish — and may not read_secret, which is the whole point of it not being
// maintainer. Developer is the mirror image: it does what CI does and cannot
// reconfigure anything.
func TestCapabilityMatrix(t *testing.T) {
	granted := map[Role][]Capability{
		RoleOwner: {
			CapReadPrivate, CapIngest, CapTriggerScan, CapPushInventory,
			CapDeleteArtifact, CapManageSource, CapManageCluster, CapReadSecret,
			CapManageMember, CapDeleteNamespace,
		},
		RoleMaintainer: {
			CapReadPrivate, CapIngest, CapTriggerScan, CapPushInventory,
			CapDeleteArtifact, CapManageSource, CapManageCluster, CapReadSecret,
		},
		RoleSecurity:  {CapReadPrivate, CapTriggerScan},
		RoleDeveloper: {CapReadPrivate, CapIngest, CapTriggerScan, CapPushInventory},
		RoleViewer:    {CapReadPrivate},
	}

	for _, r := range allRoles {
		want := make(map[Capability]bool, len(granted[r]))
		for _, c := range granted[r] {
			want[c] = true
		}
		for _, c := range allCapabilities {
			if got := r.Allows(c); got != want[c] {
				t.Errorf("%s.Allows(%s) = %v, want %v", r, c, got, want[c])
			}
		}
	}
}

// TestUnknownRoleGrantsNothing covers the row read back from a database written
// by a newer version, or a role string that arrived from a request body without
// passing Valid. Denying is the only safe answer, and it must not panic.
func TestUnknownRoleGrantsNothing(t *testing.T) {
	for _, r := range []Role{"", "admin", "Owner", "superuser"} {
		if r.Valid() {
			t.Errorf("Role(%q).Valid() = true, want false", r)
		}
		for _, c := range allCapabilities {
			if r.Allows(c) {
				t.Errorf("Role(%q).Allows(%s) = true, want false", r, c)
			}
		}
		if len(r.Capabilities()) != 0 {
			t.Errorf("Role(%q).Capabilities() = %v, want empty", r, r.Capabilities())
		}
	}
	for _, r := range allRoles {
		if !r.Valid() {
			t.Errorf("Role(%q).Valid() = false, want true", r)
		}
	}
}

// TestAllowGlobalRules covers the two installation-wide rules Allow folds in.
// They are here rather than at the call sites precisely so they can be tested
// once, and they are the pair that is easy to get half-right: an admin
// short-circuit that forgets non-members, or a viewer floor that a namespace
// owner can undo by handing out a maintainer role.
func TestAllowGlobalRules(t *testing.T) {
	tests := []struct {
		name       string
		globalRole string
		member     Role
		present    bool
		cap        Capability
		want       bool
	}{
		{"admin short-circuits without membership", "admin", "", false, CapDeleteNamespace, true},
		{"admin short-circuits a viewer membership", "admin", RoleViewer, true, CapReadSecret, true},
		{"member with the role is allowed", "member", RoleMaintainer, true, CapReadSecret, true},
		{"member without the role is denied", "member", RoleSecurity, true, CapReadSecret, false},
		{"non-member is denied even at owner role", "member", RoleOwner, false, CapReadPrivate, false},
		{"global viewer keeps reading", "viewer", RoleViewer, true, CapReadPrivate, true},
		{"global viewer reads a private namespace it maintains", "viewer", RoleMaintainer, true, CapReadPrivate, true},
		{"global viewer cannot be widened by a namespace role", "viewer", RoleMaintainer, true, CapReadSecret, false},
		{"global viewer cannot be made an owner in effect", "viewer", RoleOwner, true, CapManageMember, false},
		{"unknown global role falls through to the namespace role", "", RoleDeveloper, true, CapIngest, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Allow(tt.globalRole, tt.member, tt.present, tt.cap); got != tt.want {
				t.Errorf("Allow(%q, %q, %v, %q) = %v, want %v",
					tt.globalRole, tt.member, tt.present, tt.cap, got, tt.want)
			}
		})
	}
}

// TestGlobalRoleStringsMatchTheDatabase guards the copy of the installation-wide
// role strings this package keeps. It cannot import internal/service — that is
// the whole reason the package exists — so it reads the declaration instead. A
// rename there that did not land here would show up as a global admin quietly
// losing their short-circuit, which no behavioural test in this package can
// see because both halves would agree with each other.
func TestGlobalRoleStringsMatchTheDatabase(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean("../service/auth.go"))
	if err != nil {
		t.Fatalf("reading internal/service/auth.go: %v", err)
	}
	for name, want := range map[string]string{
		"roleAdmin":  globalRoleAdmin,
		"roleViewer": globalRoleViewer,
	} {
		re := regexp.MustCompile(name + `\s*=\s*"` + want + `"`)
		if !re.Match(src) {
			t.Errorf("internal/service/auth.go does not declare %s = %q; "+
				"authz's copy of the installation-wide role strings has drifted", name, want)
		}
	}
}

// TestPackageHasNoInternalImports enforces the constraint that makes this
// package usable from both halves of the authorization model: it may not import
// internal/api or internal/service. An import either way turns the shared table
// into a layering violation and forces one of the two callers to keep a second
// copy.
func TestPackageHasNoInternalImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, banned := range []string{
			`"github.com/pfenerty/ocidex/internal/api"`,
			`"github.com/pfenerty/ocidex/internal/service"`,
		} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s imports %s; internal/authz must be importable by both", name, banned)
			}
		}
	}
}
