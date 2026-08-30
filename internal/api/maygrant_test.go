package api

import (
	"testing"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// TestMayGrant covers the rule no request can currently exercise: only the
// owner holds manage_member today, and the owner dominates every role, so the
// API never reaches a refusal. That is exactly why it is worth a direct test —
// the day a second role gains the capability, this is the guard that has to
// already be right, and no route-level test would have been covering it.
func TestMayGrant(t *testing.T) {
	const ns = "11111111-1111-1111-1111-111111111111"

	member := func(role authz.Role) service.AuthUser {
		return service.AuthUser{
			Role:   "member",
			Grants: map[string]authz.Role{ns: role},
		}
	}

	tests := []struct {
		name  string
		user  service.AuthUser
		ns    string
		grant authz.Role
		want  bool
	}{
		{"owner grants owner", member(authz.RoleOwner), ns, authz.RoleOwner, true},
		{"owner grants viewer", member(authz.RoleOwner), ns, authz.RoleViewer, true},
		{"maintainer cannot grant owner", member(authz.RoleMaintainer), ns, authz.RoleOwner, false},
		{"maintainer grants developer", member(authz.RoleMaintainer), ns, authz.RoleDeveloper, true},
		{"security cannot grant developer", member(authz.RoleSecurity), ns, authz.RoleDeveloper, false},
		{"developer grants security", member(authz.RoleDeveloper), ns, authz.RoleSecurity, true},
		{"non-member grants nothing", service.AuthUser{Role: "member"}, ns, authz.RoleViewer, false},
		{"admin grants owner without membership", service.AuthUser{Role: roleAdmin}, ns, authz.RoleOwner, true},
		{"no namespace, no grant", member(authz.RoleOwner), "", authz.RoleViewer, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mayGrant(tt.user, tt.ns, tt.grant); got != tt.want {
				t.Errorf("mayGrant(%s in %q, %s) = %v, want %v",
					tt.user.Role, tt.ns, tt.grant, got, tt.want)
			}
		})
	}
}
