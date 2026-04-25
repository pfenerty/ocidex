package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/repository"
)

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
	upsertUserFn        func(ctx context.Context, arg repository.UpsertUserParams) (repository.OcidexUser, error)
	getUserByIDFn       func(ctx context.Context, id pgtype.UUID) (repository.OcidexUser, error)
	listUsersFn         func(ctx context.Context) ([]repository.OcidexUser, error)
	updateUserRoleFn    func(ctx context.Context, arg repository.UpdateUserRoleParams) (repository.OcidexUser, error)
	deleteExpiredFn     func(ctx context.Context) error
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

func (f *fakeAuthRepo) UpsertUser(ctx context.Context, arg repository.UpsertUserParams) (repository.OcidexUser, error) {
	if f.upsertUserFn != nil {
		return f.upsertUserFn(ctx, arg)
	}
	return repository.OcidexUser{}, nil
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

// newTestAuthService builds an authService with the given fake repo and a
// minimal config (SessionMaxAgeDays=7).
func newTestAuthService(repo repository.AuthRepository) *authService {
	return &authService{
		repo: repo,
		cfg:  &config.Config{SessionMaxAgeDays: 7},
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
				UserID:         userID,
				GithubID:       42,
				GithubUsername: "alice",
				Role:           "member",
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	user, err := svc.ValidateSession(context.Background(), "any-token")

	is.NoErr(err)
	is.Equal(user.GitHubUsername, "alice")
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

	key, err := svc.CreateAPIKey(context.Background(), pgtype.UUID{Valid: true}, "ci")

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

	_, err := svc.CreateAPIKey(context.Background(), pgtype.UUID{Valid: true}, "ci")
	is.True(err != nil)
}

func TestValidateAPIKey_Valid(t *testing.T) {
	is := is.New(t)
	userID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	keyID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	repo := &fakeAuthRepo{
		getAPIKeyByHashFn: func(_ context.Context, _ string) (repository.GetAPIKeyByHashRow, error) {
			return repository.GetAPIKeyByHashRow{
				ID:             keyID,
				UserID:         userID,
				GithubID:       7,
				GithubUsername: "bob",
				Role:           "admin",
			}, nil
		},
		touchAPIKeyFn: func(_ context.Context, _ pgtype.UUID) error { return nil },
	}
	svc := newTestAuthService(repo)

	user, err := svc.ValidateAPIKey(context.Background(), "ocidex_somekey")

	is.NoErr(err)
	is.Equal(user.GitHubUsername, "bob")
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
				ID:             userID,
				GithubUsername: "carol",
				Role:           "viewer",
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	user, err := svc.GetUser(context.Background(), userID)
	is.NoErr(err)
	is.Equal(user.GitHubUsername, "carol")
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
				{GithubUsername: "alice", Role: "admin"},
				{GithubUsername: "bob", Role: "member"},
			}, nil
		},
	}
	svc := newTestAuthService(repo)

	users, err := svc.ListUsers(context.Background())
	is.NoErr(err)
	is.Equal(len(users), 2)
	is.Equal(users[0].GitHubUsername, "alice")
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
