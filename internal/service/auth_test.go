package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository"
)

type noopPublisher struct{}

func (noopPublisher) Publish(_ context.Context, _ event.Type, _ any) {}

// ---------------------------------------------------------------------------
// Fake AuthRepository
// ---------------------------------------------------------------------------

type fakeAuthRepo struct {
	createSessionFn     func(ctx context.Context, arg repository.CreateSessionParams) (repository.Session, error)
	getSessionFn        func(ctx context.Context, hash string) (repository.GetSessionByTokenHashRow, error)
	deleteSessionFn     func(ctx context.Context, hash string) error
	createAPIKeyFn      func(ctx context.Context, arg repository.CreateAPIKeyParams) (repository.ApiKey, error)
	getAPIKeyByHashFn   func(ctx context.Context, hash string) (repository.GetAPIKeyByHashRow, error)
	touchAPIKeyFn       func(ctx context.Context, id pgtype.UUID) error
	listAPIKeysByUserFn func(ctx context.Context, userID pgtype.UUID) ([]repository.ListAPIKeysByUserRow, error)
	deleteAPIKeyFn      func(ctx context.Context, arg repository.DeleteAPIKeyParams) (int64, error)
	getUserByIdentityFn func(ctx context.Context, arg repository.GetUserByIdentityParams) (repository.OcidexUser, error)
	createUserFn        func(ctx context.Context, arg repository.CreateUserWithIdentityParams) (repository.CreateUserWithIdentityRow, error)
	touchProfileFn      func(ctx context.Context, arg repository.TouchUserProfileParams) (repository.OcidexUser, error)
	upsertIdentityFn    func(ctx context.Context, arg repository.UpsertIdentityEmailParams) error
	getUserByIDFn       func(ctx context.Context, id pgtype.UUID) (repository.OcidexUser, error)
	listUsersFn         func(ctx context.Context) ([]repository.OcidexUser, error)
	updateUserRoleFn    func(ctx context.Context, arg repository.UpdateUserRoleParams) (repository.OcidexUser, error)
	deleteExpiredFn     func(ctx context.Context) error
	listMembershipsFn   func(ctx context.Context, userID pgtype.UUID) ([]repository.NamespaceMember, error)
}

func (f *fakeAuthRepo) CreateSession(ctx context.Context, arg repository.CreateSessionParams) (repository.Session, error) {
	if f.createSessionFn != nil {
		return f.createSessionFn(ctx, arg)
	}
	return repository.Session{}, nil
}

func (f *fakeAuthRepo) GetSessionByTokenHash(ctx context.Context, hash string) (repository.GetSessionByTokenHashRow, error) {
	if f.getSessionFn != nil {
		return f.getSessionFn(ctx, hash)
	}
	return repository.GetSessionByTokenHashRow{}, errors.New("not found")
}

func (f *fakeAuthRepo) DeleteSession(ctx context.Context, hash string) error {
	if f.deleteSessionFn != nil {
		return f.deleteSessionFn(ctx, hash)
	}
	return nil
}

func (f *fakeAuthRepo) CreateAPIKey(ctx context.Context, arg repository.CreateAPIKeyParams) (repository.ApiKey, error) {
	if f.createAPIKeyFn != nil {
		return f.createAPIKeyFn(ctx, arg)
	}
	return repository.ApiKey{}, nil
}

func (f *fakeAuthRepo) GetAPIKeyByHash(ctx context.Context, hash string) (repository.GetAPIKeyByHashRow, error) {
	if f.getAPIKeyByHashFn != nil {
		return f.getAPIKeyByHashFn(ctx, hash)
	}
	return repository.GetAPIKeyByHashRow{}, errors.New("not found")
}

func (f *fakeAuthRepo) TouchAPIKeyLastUsed(ctx context.Context, id pgtype.UUID) error {
	if f.touchAPIKeyFn != nil {
		return f.touchAPIKeyFn(ctx, id)
	}
	return nil
}

func (f *fakeAuthRepo) ListAPIKeysByUser(ctx context.Context, userID pgtype.UUID) ([]repository.ListAPIKeysByUserRow, error) {
	if f.listAPIKeysByUserFn != nil {
		return f.listAPIKeysByUserFn(ctx, userID)
	}
	return nil, nil
}

func (f *fakeAuthRepo) DeleteAPIKey(ctx context.Context, arg repository.DeleteAPIKeyParams) (int64, error) {
	if f.deleteAPIKeyFn != nil {
		return f.deleteAPIKeyFn(ctx, arg)
	}
	return 1, nil
}

func (f *fakeAuthRepo) GetUserByIdentity(ctx context.Context, arg repository.GetUserByIdentityParams) (repository.OcidexUser, error) {
	if f.getUserByIdentityFn != nil {
		return f.getUserByIdentityFn(ctx, arg)
	}
	return repository.OcidexUser{}, pgx.ErrNoRows
}

func (f *fakeAuthRepo) CreateUserWithIdentity(ctx context.Context, arg repository.CreateUserWithIdentityParams) (repository.CreateUserWithIdentityRow, error) {
	if f.createUserFn != nil {
		return f.createUserFn(ctx, arg)
	}
	return repository.CreateUserWithIdentityRow{}, nil
}

func (f *fakeAuthRepo) TouchUserProfile(ctx context.Context, arg repository.TouchUserProfileParams) (repository.OcidexUser, error) {
	if f.touchProfileFn != nil {
		return f.touchProfileFn(ctx, arg)
	}
	return repository.OcidexUser{}, nil
}

func (f *fakeAuthRepo) UpsertIdentityEmail(ctx context.Context, arg repository.UpsertIdentityEmailParams) error {
	if f.upsertIdentityFn != nil {
		return f.upsertIdentityFn(ctx, arg)
	}
	return nil
}

func (f *fakeAuthRepo) GetUserByID(ctx context.Context, id pgtype.UUID) (repository.OcidexUser, error) {
	if f.getUserByIDFn != nil {
		return f.getUserByIDFn(ctx, id)
	}
	return repository.OcidexUser{}, errors.New("not found")
}

func (f *fakeAuthRepo) ListUsers(ctx context.Context) ([]repository.OcidexUser, error) {
	if f.listUsersFn != nil {
		return f.listUsersFn(ctx)
	}
	return nil, nil
}

func (f *fakeAuthRepo) UpdateUserRole(ctx context.Context, arg repository.UpdateUserRoleParams) (repository.OcidexUser, error) {
	if f.updateUserRoleFn != nil {
		return f.updateUserRoleFn(ctx, arg)
	}
	return repository.OcidexUser{Role: arg.Role}, nil
}

func (f *fakeAuthRepo) DeleteExpiredSessions(ctx context.Context) error {
	if f.deleteExpiredFn != nil {
		return f.deleteExpiredFn(ctx)
	}
	return nil
}

func (f *fakeAuthRepo) ListNamespaceMembershipsForUser(ctx context.Context, userID pgtype.UUID) ([]repository.NamespaceMember, error) {
	if f.listMembershipsFn != nil {
		return f.listMembershipsFn(ctx, userID)
	}
	return nil, nil
}

// newTestAuthService builds an authService with the given fake repo and a
// minimal config (SessionMaxAgeDays=7).
func newTestAuthService(repo repository.AuthRepository) *authService {
	return &authService{
		repo:      repo,
		cfg:       &config.Config{SessionMaxAgeDays: 7},
		publisher: noopPublisher{},
	}
}

// ---------------------------------------------------------------------------
// Session tests
// ---------------------------------------------------------------------------

func TestCreateSession_ReturnsNonEmptyToken(t *testing.T) {
	is := is.New(t)
	var storedHash string
	repo := &fakeAuthRepo{
		createSessionFn: func(_ context.Context, arg repository.CreateSessionParams) (repository.Session, error) {
			storedHash = arg.TokenHash
			return repository.Session{}, nil
		},
	}
	svc := newTestAuthService(repo)

	token, err := svc.CreateSession(context.Background(), pgtype.UUID{Valid: true})

	is.NoErr(err)
	is.True(token != "")
	is.True(storedHash != "")
	is.True(storedHash != token) // stored hash differs from plaintext
}

func TestCreateSession_RepoError(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		createSessionFn: func(_ context.Context, _ repository.CreateSessionParams) (repository.Session, error) {
			return repository.Session{}, errors.New("db error")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.CreateSession(context.Background(), pgtype.UUID{Valid: true})
	is.True(err != nil)
}

func TestValidateSession_Valid(t *testing.T) {
	is := is.New(t)
	userID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	repo := &fakeAuthRepo{
		getSessionFn: func(_ context.Context, hash string) (repository.GetSessionByTokenHashRow, error) {
			return repository.GetSessionByTokenHashRow{
				UserID:      userID,
				DisplayName: pgtype.Text{String: "alice", Valid: true},
				Role:        "member",
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	user, err := svc.ValidateSession(context.Background(), "any-token")

	is.NoErr(err)
	is.Equal(user.DisplayName, "alice")
	is.Equal(user.Role, "member")
	is.Equal(user.ID, userID)
}

func TestValidateSession_NotFound(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		getSessionFn: func(_ context.Context, _ string) (repository.GetSessionByTokenHashRow, error) {
			return repository.GetSessionByTokenHashRow{}, errors.New("no rows")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.ValidateSession(context.Background(), "bad-token")
	is.True(err != nil)
}

func TestValidateSession_HashesToken(t *testing.T) {
	is := is.New(t)
	var receivedHash string
	repo := &fakeAuthRepo{
		getSessionFn: func(_ context.Context, hash string) (repository.GetSessionByTokenHashRow, error) {
			receivedHash = hash
			return repository.GetSessionByTokenHashRow{Role: "member"}, nil
		},
	}
	svc := newTestAuthService(repo)
	token := "my-plaintext-token"

	_, err := svc.ValidateSession(context.Background(), token)

	is.NoErr(err)
	is.True(receivedHash != token)           // service hashes before lookup
	is.Equal(receivedHash, sha256hex(token)) // hashes using SHA-256
}

// ---------------------------------------------------------------------------
// API key tests
// ---------------------------------------------------------------------------

func TestCreateAPIKey_PrefixAndFormat(t *testing.T) {
	is := is.New(t)
	var storedHash, storedPrefix string
	repo := &fakeAuthRepo{
		createAPIKeyFn: func(_ context.Context, arg repository.CreateAPIKeyParams) (repository.ApiKey, error) {
			storedHash = arg.KeyHash
			storedPrefix = arg.Prefix
			return repository.ApiKey{}, nil
		},
	}
	svc := newTestAuthService(repo)

	key, err := svc.CreateAPIKey(context.Background(), pgtype.UUID{Valid: true}, "ci", nil)

	is.NoErr(err)
	is.True(strings.HasPrefix(key, "ocidex_")) // plaintext starts with prefix
	is.True(storedHash != key)                 // stored hash differs from plaintext
	is.True(storedPrefix != "")                // prefix stored for display
	is.True(strings.HasPrefix(storedPrefix, "ocidex_"))
}

func TestCreateAPIKey_RepoError(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		createAPIKeyFn: func(_ context.Context, _ repository.CreateAPIKeyParams) (repository.ApiKey, error) {
			return repository.ApiKey{}, errors.New("db error")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.CreateAPIKey(context.Background(), pgtype.UUID{Valid: true}, "ci", nil)
	is.True(err != nil)
}

func TestValidateAPIKey_Valid(t *testing.T) {
	is := is.New(t)
	userID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	keyID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	repo := &fakeAuthRepo{
		getAPIKeyByHashFn: func(_ context.Context, _ string) (repository.GetAPIKeyByHashRow, error) {
			return repository.GetAPIKeyByHashRow{
				ID:          keyID,
				UserID:      userID,
				DisplayName: pgtype.Text{String: "bob", Valid: true},
				Role:        "admin",
			}, nil
		},
		touchAPIKeyFn: func(_ context.Context, _ pgtype.UUID) error { return nil },
	}
	svc := newTestAuthService(repo)

	user, err := svc.ValidateAPIKey(context.Background(), "ocidex_somekey")

	is.NoErr(err)
	is.Equal(user.DisplayName, "bob")
	is.Equal(user.Role, "admin")
}

func TestValidateAPIKey_NotFound(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		getAPIKeyByHashFn: func(_ context.Context, _ string) (repository.GetAPIKeyByHashRow, error) {
			return repository.GetAPIKeyByHashRow{}, errors.New("not found")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.ValidateAPIKey(context.Background(), "ocidex_wrong")
	is.True(err != nil)
}

func TestValidateAPIKey_HashesKey(t *testing.T) {
	is := is.New(t)
	var receivedHash string
	rawKey := "ocidex_myrawkey"
	repo := &fakeAuthRepo{
		getAPIKeyByHashFn: func(_ context.Context, hash string) (repository.GetAPIKeyByHashRow, error) {
			receivedHash = hash
			return repository.GetAPIKeyByHashRow{Role: "member"}, nil
		},
		touchAPIKeyFn: func(_ context.Context, _ pgtype.UUID) error { return nil },
	}
	svc := newTestAuthService(repo)

	_, _ = svc.ValidateAPIKey(context.Background(), rawKey)

	is.True(receivedHash != rawKey)           // service hashes before lookup
	is.Equal(receivedHash, sha256hex(rawKey)) // correct hash used
}

// ---------------------------------------------------------------------------
// UpdateUserRole tests
// ---------------------------------------------------------------------------

func TestUpdateUserRole_ValidRoles(t *testing.T) {
	for _, role := range []string{"admin", "member", "viewer"} {
		t.Run(role, func(t *testing.T) {
			is := is.New(t)
			repo := &fakeAuthRepo{
				updateUserRoleFn: func(_ context.Context, arg repository.UpdateUserRoleParams) (repository.OcidexUser, error) {
					return repository.OcidexUser{Role: arg.Role}, nil
				},
			}
			svc := newTestAuthService(repo)

			user, err := svc.UpdateUserRole(context.Background(), pgtype.UUID{Valid: true}, role)
			is.NoErr(err)
			is.Equal(user.Role, role)
		})
	}
}

func TestUpdateUserRole_InvalidRole(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{}
	svc := newTestAuthService(repo)

	_, err := svc.UpdateUserRole(context.Background(), pgtype.UUID{Valid: true}, "superuser")
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// DeleteSession tests
// ---------------------------------------------------------------------------

func TestDeleteSession_Delegates(t *testing.T) {
	is := is.New(t)
	var called bool
	repo := &fakeAuthRepo{
		deleteSessionFn: func(_ context.Context, hash string) error {
			called = true
			is.True(hash != "plain") // service hashes before delete
			return nil
		},
	}
	svc := newTestAuthService(repo)

	err := svc.DeleteSession(context.Background(), "plain")
	is.NoErr(err)
	is.True(called)
}

// ---------------------------------------------------------------------------
// ListAPIKeys tests
// ---------------------------------------------------------------------------

func TestListAPIKeys_ReturnsKeys(t *testing.T) {
	is := is.New(t)
	userID := pgtype.UUID{Bytes: [16]byte{5}, Valid: true}
	keyID := pgtype.UUID{Bytes: [16]byte{6}, Valid: true}
	repo := &fakeAuthRepo{
		listAPIKeysByUserFn: func(_ context.Context, _ pgtype.UUID) ([]repository.ListAPIKeysByUserRow, error) {
			return []repository.ListAPIKeysByUserRow{
				{ID: keyID, Name: "ci", Prefix: "ocidex_"},
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	keys, err := svc.ListAPIKeys(context.Background(), userID)
	is.NoErr(err)
	is.Equal(len(keys), 1)
	is.Equal(keys[0].Name, "ci")
}

func TestListAPIKeys_RepoError(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		listAPIKeysByUserFn: func(_ context.Context, _ pgtype.UUID) ([]repository.ListAPIKeysByUserRow, error) {
			return nil, errors.New("db error")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.ListAPIKeys(context.Background(), pgtype.UUID{Valid: true})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// DeleteAPIKey tests
// ---------------------------------------------------------------------------

func TestDeleteAPIKey_Found(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		deleteAPIKeyFn: func(_ context.Context, _ repository.DeleteAPIKeyParams) (int64, error) {
			return 1, nil
		},
	}
	svc := newTestAuthService(repo)

	err := svc.DeleteAPIKey(context.Background(), pgtype.UUID{Valid: true}, pgtype.UUID{Valid: true})
	is.NoErr(err)
}

func TestDeleteAPIKey_NotFound(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		deleteAPIKeyFn: func(_ context.Context, _ repository.DeleteAPIKeyParams) (int64, error) {
			return 0, nil
		},
	}
	svc := newTestAuthService(repo)

	err := svc.DeleteAPIKey(context.Background(), pgtype.UUID{Valid: true}, pgtype.UUID{Valid: true})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// GetUser tests
// ---------------------------------------------------------------------------

func TestGetUser_Found(t *testing.T) {
	is := is.New(t)
	userID := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}
	repo := &fakeAuthRepo{
		getUserByIDFn: func(_ context.Context, _ pgtype.UUID) (repository.OcidexUser, error) {
			return repository.OcidexUser{
				ID:          userID,
				DisplayName: pgtype.Text{String: "carol", Valid: true},
				Role:        "viewer",
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	user, err := svc.GetUser(context.Background(), userID)
	is.NoErr(err)
	is.Equal(user.DisplayName, "carol")
	is.Equal(user.Role, "viewer")
}

func TestGetUser_NotFound(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		getUserByIDFn: func(_ context.Context, _ pgtype.UUID) (repository.OcidexUser, error) {
			return repository.OcidexUser{}, errors.New("not found")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.GetUser(context.Background(), pgtype.UUID{Valid: true})
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// ListUsers tests
// ---------------------------------------------------------------------------

func TestListUsers_ReturnsList(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		listUsersFn: func(_ context.Context) ([]repository.OcidexUser, error) {
			return []repository.OcidexUser{
				{DisplayName: pgtype.Text{String: "alice", Valid: true}, Role: "admin"},
				{DisplayName: pgtype.Text{String: "bob", Valid: true}, Role: "member"},
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	users, err := svc.ListUsers(context.Background())
	is.NoErr(err)
	is.Equal(len(users), 2)
	is.Equal(users[0].DisplayName, "alice")
}

func TestListUsers_RepoError(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		listUsersFn: func(_ context.Context) ([]repository.OcidexUser, error) {
			return nil, errors.New("db error")
		},
	}
	svc := newTestAuthService(repo)

	_, err := svc.ListUsers(context.Background())
	is.True(err != nil)
}

// ---------------------------------------------------------------------------
// CleanExpiredSessions tests
// ---------------------------------------------------------------------------

func TestCleanExpiredSessions_Delegates(t *testing.T) {
	is := is.New(t)
	var called bool
	repo := &fakeAuthRepo{
		deleteExpiredFn: func(_ context.Context) error {
			called = true
			return nil
		},
	}
	svc := newTestAuthService(repo)

	err := svc.CleanExpiredSessions(context.Background())
	is.NoErr(err)
	is.True(called)
}

// ---------------------------------------------------------------------------
// API key capabilities (ADR-046)
// ---------------------------------------------------------------------------

func TestCreateAPIKey_CapabilityCeiling(t *testing.T) {
	tests := []struct {
		name    string
		caps    []authz.Capability
		want    []string
		wantErr bool
	}{
		{
			// "No ceiling" is not "no capabilities" — it is "whatever I can
			// do", which the validation-time intersection then narrows.
			name: "an unspecified ceiling stores every capability",
			caps: nil,
			want: authz.Strings(authz.AllCapabilities()),
		},
		{
			name: "a named ceiling is stored verbatim",
			caps: []authz.Capability{authz.CapIngest, authz.CapReadPrivate},
			want: []string{"ingest", "read_private"},
		},
		{
			name:    "an unknown capability is rejected, not dropped",
			caps:    []authz.Capability{authz.CapIngest, authz.Capability("delete_everything")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			var stored []string
			called := false
			repo := &fakeAuthRepo{
				createAPIKeyFn: func(_ context.Context, arg repository.CreateAPIKeyParams) (repository.ApiKey, error) {
					called = true
					stored = arg.Capabilities
					return repository.ApiKey{}, nil
				},
			}
			svc := newTestAuthService(repo)

			_, err := svc.CreateAPIKey(context.Background(), pgtype.UUID{Valid: true}, "ci", tt.caps)

			if tt.wantErr {
				var verr *ValidationError
				is.True(errors.As(err, &verr)) // a bad capability is a 422, not a 500
				is.True(!called)               // and nothing is minted
				return
			}
			is.NoErr(err)
			is.Equal(stored, tt.want)
		})
	}
}

func TestValidateAPIKey_CapabilitiesNarrowOnly(t *testing.T) {
	tests := []struct {
		name string
		row  []string
		want []authz.Capability
	}{
		{
			name: "known capabilities come back as they are",
			row:  []string{"read_private", "ingest"},
			want: []authz.Capability{authz.CapReadPrivate, authz.CapIngest},
		},
		{
			// A row written by a newer build. Dropping the stranger narrows the
			// key; keeping or honouring it would fail open on a downgrade.
			name: "an unrecognised capability is dropped",
			row:  []string{"read_private", "read_minds"},
			want: []authz.Capability{authz.CapReadPrivate},
		},
		{
			name: "a key that carries nothing carries nothing",
			row:  nil,
			want: []authz.Capability{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			repo := &fakeAuthRepo{
				getAPIKeyByHashFn: func(_ context.Context, _ string) (repository.GetAPIKeyByHashRow, error) {
					return repository.GetAPIKeyByHashRow{Role: "member", Capabilities: tt.row}, nil
				},
				touchAPIKeyFn: func(_ context.Context, _ pgtype.UUID) error { return nil },
			}
			svc := newTestAuthService(repo)

			user, err := svc.ValidateAPIKey(context.Background(), "ocidex_k")

			is.NoErr(err)
			is.True(user.APIKeyAuth) // the ceiling only means anything on a key
			is.Equal(user.APIKeyCaps, tt.want)
		})
	}
}
