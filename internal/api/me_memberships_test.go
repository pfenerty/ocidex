package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// GET /users/me reports the caller's own namespace memberships so the UI can
// tell what kind of user is signed in and order the Workspace accordingly
// (ocidex-y0hg.9). The rows come off the request context, which the
// authenticate middleware already populated — the handler must not reach for
// the database, and must not invent an ordering that changes per request.
func TestGetMeReportsMembershipsFromTheRequestsOwnGrants(t *testing.T) {
	tests := []struct {
		name   string
		grants map[string]authz.Role
		want   []MyMembership
	}{
		{
			name:   "no memberships is an empty list, not null",
			grants: map[string]authz.Role{},
			want:   []MyMembership{},
		},
		{
			// Map iteration order differs per range, so an unsorted handler
			// would reshuffle this response between two identical requests.
			name: "sorted by namespace ID",
			grants: map[string]authz.Role{
				"cccccccc-0000-0000-0000-000000000000": authz.RoleViewer,
				"aaaaaaaa-0000-0000-0000-000000000000": authz.RoleSecurity,
				"bbbbbbbb-0000-0000-0000-000000000000": authz.RoleDeveloper,
			},
			want: []MyMembership{
				{NamespaceID: "aaaaaaaa-0000-0000-0000-000000000000", Role: "security"},
				{NamespaceID: "bbbbbbbb-0000-0000-0000-000000000000", Role: "developer"},
				{NamespaceID: "cccccccc-0000-0000-0000-000000000000", Role: "viewer"},
			},
		},
		{
			// LoadGrants keeps a role string it does not recognise rather than
			// dropping the row; the handler passes it through for the same
			// reason. It grants nothing either way.
			name:   "an unknown role passes through",
			grants: map[string]authz.Role{"dddddddd-0000-0000-0000-000000000000": authz.Role("auditor")},
			want: []MyMembership{
				{NamespaceID: "dddddddd-0000-0000-0000-000000000000", Role: "auditor"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			user := service.AuthUser{
				ID:             pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
				GitHubUsername: "octocat",
				Role:           "member",
				Grants:         tt.grants,
			}
			ctx := context.WithValue(context.Background(), ctxKeyUser{}, user)

			out, err := (&Handler{}).GetMe(ctx, nil)
			is.NoErr(err)
			is.Equal(out.Body.GitHubUsername, "octocat")
			is.Equal(out.Body.Memberships, tt.want) // memberships did not match the caller's grants
		})
	}
}
