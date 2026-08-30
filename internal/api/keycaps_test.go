package api

import (
	"testing"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

const keyNamespace = "11111111-1111-1111-1111-111111111111"

// session is the caller as themselves: no key, so no ceiling.
func session(globalRole string, role authz.Role) service.AuthUser {
	return service.AuthUser{
		Role:   globalRole,
		Grants: map[string]authz.Role{keyNamespace: role},
	}
}

// key is the same caller presenting an API key that declares caps.
func key(globalRole string, role authz.Role, caps ...authz.Capability) service.AuthUser {
	u := session(globalRole, role)
	u.APIKeyAuth = true
	u.APIKeyCaps = caps
	return u
}

// TestKeyCeilingNarrowsButNeverWidens is the whole point of putting
// capabilities on an API key: the key is a ceiling over what its owner may do,
// and the two constraints multiply rather than override each other.
func TestKeyCeilingNarrowsButNeverWidens(t *testing.T) {
	tests := []struct {
		name string
		user service.AuthUser
		cap  authz.Capability
		want bool
	}{
		{
			name: "a session carries no ceiling",
			user: session("member", authz.RoleDeveloper),
			cap:  authz.CapIngest,
			want: true,
		},
		{
			name: "a key holding the capability its owner holds is admitted",
			user: key("member", authz.RoleDeveloper, authz.CapIngest),
			cap:  authz.CapIngest,
			want: true,
		},
		{
			// The ADR-044 gap this story closes: an ingest key used to be
			// "read-write", which also meant push_inventory.
			name: "an ingest-only key cannot push inventory",
			user: key("member", authz.RoleDeveloper, authz.CapIngest),
			cap:  authz.CapPushInventory,
			want: false,
		},
		{
			// The other half: a key can never exceed live membership, which is
			// what makes a demotion take effect without a key rotation.
			name: "a wide key on a viewer's membership cannot ingest",
			user: key("member", authz.RoleViewer, authz.AllCapabilities()...),
			cap:  authz.CapIngest,
			want: false,
		},
		{
			name: "a wide key on a viewer's membership can still read",
			user: key("member", authz.RoleViewer, authz.AllCapabilities()...),
			cap:  authz.CapReadPrivate,
			want: true,
		},
		{
			// authz.Allow short-circuits an installation admin. The ceiling is
			// applied before it precisely so that short-circuit cannot restore
			// a capability the admin deliberately left off their own key.
			name: "an admin's narrow key does not inherit the admin short-circuit",
			user: key("admin", "", authz.CapReadPrivate),
			cap:  authz.CapDeleteNamespace,
			want: false,
		},
		{
			name: "an admin's session still short-circuits",
			user: session("admin", ""),
			cap:  authz.CapDeleteNamespace,
			want: true,
		},
		{
			name: "a key carrying nothing is a deny even for its own owner",
			user: key("member", authz.RoleOwner),
			cap:  authz.CapReadPrivate,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := can(tt.user, keyNamespace, tt.cap); got != tt.want {
				t.Errorf("can(%s) = %v, want %v", tt.cap, got, tt.want)
			}
		})
	}
}

// TestIsWriteAllowedAsksOnlyWhetherAnythingMutates keeps RequireWrite the
// coarse gate it has always been. The per-operation capability is what narrows
// an individual endpoint; this must not start second-guessing it, or the ~40
// operations declaring Write would each need their own answer here.
func TestIsWriteAllowedAsksOnlyWhetherAnythingMutates(t *testing.T) {
	tests := []struct {
		name string
		user service.AuthUser
		want bool
	}{
		{"a session always writes", session("member", authz.RoleOwner), true},
		{"a read-only key does not", key("member", authz.RoleOwner, authz.CapReadPrivate), false},
		{"an empty key does not", key("member", authz.RoleOwner), false},
		{"one mutating capability is enough", key("member", authz.RoleOwner, authz.CapReadPrivate, authz.CapIngest), true},
		{
			// Deliberate: the coarse gate passes and the operation's own
			// capability check is what refuses. Answering false here would
			// turn every unrelated write into a 403 with the wrong message.
			name: "a key for an unrelated write still passes the coarse gate",
			user: key("member", authz.RoleOwner, authz.CapTriggerScan),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWriteAllowed(tt.user); got != tt.want {
				t.Errorf("isWriteAllowed = %v, want %v", got, tt.want)
			}
		})
	}
}
