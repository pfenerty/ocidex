package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/auth"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/repository"
)

// stubProvider hands back a fixed identity, so a linking test exercises the
// account rules rather than an OAuth round trip.
type stubProvider struct {
	name string
	id   auth.Identity
	err  error
}

func (p stubProvider) Name() string { return p.name }
func (p stubProvider) AuthURL(state, _ string) string {
	return "https://issuer.test/authorize?state=" + state
}
func (p stubProvider) Exchange(_ context.Context, _, _ string) (auth.Identity, error) {
	return p.id, p.err
}

func newLinkService(repo repository.AuthRepository, providers ...auth.Provider) *authService {
	byName := make(map[string]auth.Provider, len(providers))
	for _, p := range providers {
		byName[p.Name()] = p
	}
	return &authService{
		repo:      repo,
		cfg:       &config.Config{SessionMaxAgeDays: 7},
		publisher: noopPublisher{},
		providers: byName,
	}
}

func userID(b byte) pgtype.UUID {
	var id pgtype.UUID
	id.Bytes[0] = b
	id.Valid = true
	return id
}

func linkableProvider() stubProvider {
	return stubProvider{
		name: "oidc:corp",
		id: auth.Identity{
			Provider: "oidc:corp",
			Subject:  "sub-1",
			Email:    "a@corp.test",
		},
	}
}

func TestLinkIdentity_CreatesRowWhenUnknown(t *testing.T) {
	is := is.New(t)
	var got repository.CreateIdentityParams
	repo := &fakeAuthRepo{
		createIdentityFn: func(_ context.Context, arg repository.CreateIdentityParams) (repository.UserIdentity, error) {
			got = arg
			return repository.UserIdentity{ID: userID(9), Provider: arg.Provider, Subject: arg.Subject}, nil
		},
	}
	svc := newLinkService(repo, linkableProvider())

	linked, err := svc.LinkIdentity(context.Background(), userID(1), "oidc:corp", "code", "verifier")
	is.NoErr(err)
	is.Equal(linked.Provider, "oidc:corp")
	is.Equal(got.UserID, userID(1))
	is.Equal(got.Subject, "sub-1")
	is.Equal(got.Email.String, "a@corp.test")
}

func TestLinkIdentity_RefusesIdentityHeldByAnotherAccount(t *testing.T) {
	is := is.New(t)
	created := false
	repo := &fakeAuthRepo{
		getIdentityFn: func(_ context.Context, _ repository.GetIdentityParams) (repository.UserIdentity, error) {
			return repository.UserIdentity{ID: userID(9), UserID: userID(2)}, nil
		},
		createIdentityFn: func(_ context.Context, _ repository.CreateIdentityParams) (repository.UserIdentity, error) {
			created = true
			return repository.UserIdentity{}, nil
		},
	}
	svc := newLinkService(repo, linkableProvider())

	_, err := svc.LinkIdentity(context.Background(), userID(1), "oidc:corp", "code", "verifier")
	// Refused, not merged: absorbing the other account is exactly the attack
	// this rule exists to stop.
	is.True(errors.Is(err, ErrConflict))
	is.True(!created)
}

func TestLinkIdentity_IsIdempotentForTheSameAccount(t *testing.T) {
	is := is.New(t)
	created := false
	repo := &fakeAuthRepo{
		getIdentityFn: func(_ context.Context, _ repository.GetIdentityParams) (repository.UserIdentity, error) {
			return repository.UserIdentity{ID: userID(9), UserID: userID(1), Provider: "oidc:corp"}, nil
		},
		createIdentityFn: func(_ context.Context, _ repository.CreateIdentityParams) (repository.UserIdentity, error) {
			created = true
			return repository.UserIdentity{}, nil
		},
	}
	svc := newLinkService(repo, linkableProvider())

	linked, err := svc.LinkIdentity(context.Background(), userID(1), "oidc:corp", "code", "verifier")
	is.NoErr(err)
	is.Equal(linked.Provider, "oidc:corp")
	is.True(!created)
}

func TestLinkIdentity_RejectsUnknownProvider(t *testing.T) {
	is := is.New(t)
	svc := newLinkService(&fakeAuthRepo{}, linkableProvider())

	_, err := svc.LinkIdentity(context.Background(), userID(1), "oidc:nope", "code", "verifier")
	var valErr *ValidationError
	is.True(errors.As(err, &valErr))
}

func TestUnlinkIdentity_RefusesTheLastOne(t *testing.T) {
	is := is.New(t)
	deleted := false
	repo := &fakeAuthRepo{
		countIdentitiesFn: func(_ context.Context, _ pgtype.UUID) (int64, error) { return 1, nil },
		deleteIdentityFn: func(_ context.Context, _ repository.DeleteIdentityParams) (int64, error) {
			deleted = true
			return 1, nil
		},
	}
	svc := newLinkService(repo)

	err := svc.UnlinkIdentity(context.Background(), userID(1), userID(9))
	// The account would survive, still owning namespaces, with nobody able to
	// sign in to it.
	is.True(errors.Is(err, ErrConflict))
	is.True(!deleted)
}

func TestUnlinkIdentity_RemovesOneOfSeveral(t *testing.T) {
	is := is.New(t)
	var got repository.DeleteIdentityParams
	repo := &fakeAuthRepo{
		countIdentitiesFn: func(_ context.Context, _ pgtype.UUID) (int64, error) { return 2, nil },
		deleteIdentityFn: func(_ context.Context, arg repository.DeleteIdentityParams) (int64, error) {
			got = arg
			return 1, nil
		},
	}
	svc := newLinkService(repo)

	is.NoErr(svc.UnlinkIdentity(context.Background(), userID(1), userID(9)))
	// Scoped by owner as well as id, so one account cannot unlink another's.
	is.Equal(got.UserID, userID(1))
	is.Equal(got.ID, userID(9))
}

func TestUnlinkIdentity_NotFoundWhenRowIsNotTheCallers(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		countIdentitiesFn: func(_ context.Context, _ pgtype.UUID) (int64, error) { return 2, nil },
		deleteIdentityFn: func(_ context.Context, _ repository.DeleteIdentityParams) (int64, error) {
			return 0, nil
		},
	}
	svc := newLinkService(repo)

	is.True(errors.Is(svc.UnlinkIdentity(context.Background(), userID(1), userID(9)), ErrNotFound))
}

func TestListIdentities_MapsRows(t *testing.T) {
	is := is.New(t)
	repo := &fakeAuthRepo{
		listIdentitiesFn: func(_ context.Context, _ pgtype.UUID) ([]repository.ListIdentitiesByUserRow, error) {
			return []repository.ListIdentitiesByUserRow{
				{ID: userID(9), Provider: "github", Subject: "16961380"},
				{ID: userID(8), Provider: "oidc:corp", Subject: "sub-1", Email: pgtype.Text{String: "a@corp.test", Valid: true}},
			}, nil
		},
	}
	svc := newLinkService(repo)

	out, err := svc.ListIdentities(context.Background(), userID(1))
	is.NoErr(err)
	is.Equal(len(out), 2)
	is.Equal(out[0].Provider, "github")
	is.Equal(out[1].Email, "a@corp.test")
}

func TestProviderNames_AreSorted(t *testing.T) {
	is := is.New(t)
	svc := newLinkService(&fakeAuthRepo{},
		stubProvider{name: "oidc:corp"}, stubProvider{name: "github"})

	is.Equal(svc.ProviderNames(), []string{"github", "oidc:corp"})
}
