package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/auth"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/repository"
)

// TestExchangeCodeForUser_BootstrapAdmins covers ocidex-avsz.1: a listed
// (provider, subject) is promoted at sign-in, and nothing else is — not the same
// subject under another issuer, and not a matching email.
func TestExchangeCodeForUser_BootstrapAdmins(t *testing.T) {
	listed := []config.IdentityRef{
		{Provider: "github", Subject: "42"},
		{Provider: "oidc:corp", Subject: "admin@corp.test"},
	}
	tests := []struct {
		name     string
		id       auth.Identity
		role     string
		wantRole string
		promoted bool
	}{
		{
			name:     "listed identity is promoted",
			id:       auth.Identity{Provider: "github", Subject: "42"},
			role:     roleViewer,
			wantRole: roleAdmin,
			promoted: true,
		},
		{
			name:     "same subject under another provider is not",
			id:       auth.Identity{Provider: "oidc:other", Subject: "42"},
			role:     roleViewer,
			wantRole: roleViewer,
		},
		{
			name:     "matching email is not",
			id:       auth.Identity{Provider: "oidc:corp", Subject: "sub-9", Email: "admin@corp.test"},
			role:     roleViewer,
			wantRole: roleViewer,
		},
		{
			name:     "existing admin is left alone",
			id:       auth.Identity{Provider: "github", Subject: "42"},
			role:     roleAdmin,
			wantRole: roleAdmin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			var promoted bool
			repo := &fakeAuthRepo{
				getUserByIdentityFn: func(_ context.Context, _ repository.GetUserByIdentityParams) (repository.OcidexUser, error) {
					return repository.OcidexUser{ID: userID(1), Role: tt.role}, nil
				},
				touchProfileFn: func(_ context.Context, arg repository.TouchUserProfileParams) (repository.OcidexUser, error) {
					return repository.OcidexUser{ID: arg.ID, Role: tt.role}, nil
				},
				updateUserRoleFn: func(_ context.Context, arg repository.UpdateUserRoleParams) (repository.OcidexUser, error) {
					promoted = true
					is.Equal(arg.ID, userID(1))
					return repository.OcidexUser{ID: arg.ID, Role: arg.Role}, nil
				},
			}
			svc := newLinkService(repo, stubProvider{name: tt.id.Provider, id: tt.id})
			svc.cfg.BootstrapAdmins = listed

			u, err := svc.ExchangeCodeForUser(context.Background(), tt.id.Provider, "code", "verifier")
			is.NoErr(err)
			is.Equal(u.Role, tt.wantRole)
			is.Equal(promoted, tt.promoted)
		})
	}
}

// TestExchangeCodeForUser_BootstrapAdminFirstSignIn: an account listed before it
// exists is promoted on the sign-in that creates it.
func TestExchangeCodeForUser_BootstrapAdminFirstSignIn(t *testing.T) {
	is := is.New(t)
	id := auth.Identity{Provider: "github", Subject: "42"}
	repo := &fakeAuthRepo{
		createUserFn: func(_ context.Context, _ repository.CreateUserWithIdentityParams) (repository.CreateUserWithIdentityRow, error) {
			return repository.CreateUserWithIdentityRow{ID: userID(2), Role: roleViewer}, nil
		},
	}
	svc := newLinkService(repo, stubProvider{name: "github", id: id})
	svc.cfg.BootstrapAdmins = []config.IdentityRef{{Provider: "github", Subject: "42"}}

	u, err := svc.ExchangeCodeForUser(context.Background(), "github", "code", "verifier")
	is.NoErr(err)
	is.Equal(u.ID, userID(2))
	is.Equal(u.Role, roleAdmin)
}

// TestExchangeCodeForUser_SignupExisting covers ocidex-avsz.4: with sign-up
// closed, an account that exists signs in, an unknown identity is refused
// without an account being created, and a BOOTSTRAP_ADMINS identity is still
// provisioned.
func TestExchangeCodeForUser_SignupExisting(t *testing.T) {
	tests := []struct {
		name     string
		id       auth.Identity
		known    bool
		wantErr  error
		wantRole string
		wantMint bool
	}{
		{name: "existing account signs in", id: auth.Identity{Provider: "github", Subject: "7"}, known: true, wantRole: roleViewer},
		{name: "unknown identity refused", id: auth.Identity{Provider: "github", Subject: "8"}, wantErr: ErrSignupClosed},
		{name: "bootstrap admin provisioned", id: auth.Identity{Provider: "github", Subject: "42"}, wantRole: roleAdmin, wantMint: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			minted := false
			repo := &fakeAuthRepo{
				getUserByIdentityFn: func(_ context.Context, _ repository.GetUserByIdentityParams) (repository.OcidexUser, error) {
					if tt.known {
						return repository.OcidexUser{ID: userID(1), Role: roleViewer}, nil
					}
					return repository.OcidexUser{}, pgx.ErrNoRows
				},
				touchProfileFn: func(_ context.Context, arg repository.TouchUserProfileParams) (repository.OcidexUser, error) {
					return repository.OcidexUser{ID: arg.ID, Role: roleViewer}, nil
				},
				createUserFn: func(_ context.Context, _ repository.CreateUserWithIdentityParams) (repository.CreateUserWithIdentityRow, error) {
					minted = true
					return repository.CreateUserWithIdentityRow{ID: userID(2), Role: roleViewer}, nil
				},
			}
			svc := newLinkService(repo, stubProvider{name: "github", id: tt.id})
			svc.cfg.SignupMode = config.SignupExisting
			svc.cfg.BootstrapAdmins = []config.IdentityRef{{Provider: "github", Subject: "42"}}

			u, err := svc.ExchangeCodeForUser(context.Background(), "github", "code", "verifier")
			is.Equal(minted, tt.wantMint)
			if tt.wantErr != nil {
				is.True(errors.Is(err, tt.wantErr))
				return
			}
			is.NoErr(err)
			is.Equal(u.Role, tt.wantRole)
		})
	}
}
