package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// ---------------------------------------------------------------------------
// Fake RegistryRepository
// ---------------------------------------------------------------------------

type fakeRegistryRepo struct {
	createFn     func(ctx context.Context, arg repository.CreateRegistryParams) (repository.Registry, error)
	getFn        func(ctx context.Context, id pgtype.UUID) (repository.Registry, error)
	listFn       func(ctx context.Context, arg repository.ListRegistriesParams) ([]repository.Registry, error)
	updateFn     func(ctx context.Context, arg repository.UpdateRegistryParams) (repository.Registry, error)
	setEnabledFn func(ctx context.Context, arg repository.SetRegistryEnabledParams) (repository.Registry, error)
	deleteFn     func(ctx context.Context, id pgtype.UUID) (int64, error)
	listPollFn   func(ctx context.Context) ([]repository.Registry, error)
	markPolledFn func(ctx context.Context, id pgtype.UUID) (repository.Registry, error)
}

func (f *fakeRegistryRepo) CreateRegistry(ctx context.Context, arg repository.CreateRegistryParams) (repository.Registry, error) {
	if f.createFn != nil {
		return f.createFn(ctx, arg)
	}
	return repository.Registry{Visibility: arg.Visibility, Name: arg.Name, Type: arg.Type, Url: arg.Url, ScanMode: arg.ScanMode}, nil
}

func (f *fakeRegistryRepo) GetRegistry(ctx context.Context, id pgtype.UUID) (repository.Registry, error) {
	if f.getFn != nil {
		return f.getFn(ctx, id)
	}
	return repository.Registry{}, errors.New("not found")
}

func (f *fakeRegistryRepo) ListRegistries(ctx context.Context, arg repository.ListRegistriesParams) ([]repository.Registry, error) {
	if f.listFn != nil {
		return f.listFn(ctx, arg)
	}
	return nil, nil
}

func (f *fakeRegistryRepo) UpdateRegistry(ctx context.Context, arg repository.UpdateRegistryParams) (repository.Registry, error) {
	if f.updateFn != nil {
		return f.updateFn(ctx, arg)
	}
	return repository.Registry{}, nil
}

func (f *fakeRegistryRepo) SetRegistryEnabled(ctx context.Context, arg repository.SetRegistryEnabledParams) (repository.Registry, error) {
	if f.setEnabledFn != nil {
		return f.setEnabledFn(ctx, arg)
	}
	return repository.Registry{}, nil
}

func (f *fakeRegistryRepo) DeleteRegistry(ctx context.Context, id pgtype.UUID) (int64, error) {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, id)
	}
	return 1, nil
}

func (f *fakeRegistryRepo) ListPollableRegistries(ctx context.Context) ([]repository.Registry, error) {
	if f.listPollFn != nil {
		return f.listPollFn(ctx)
	}
	return nil, nil
}

func (f *fakeRegistryRepo) UpdateRegistryLastPolled(ctx context.Context, id pgtype.UUID) (repository.Registry, error) {
	if f.markPolledFn != nil {
		return f.markPolledFn(ctx, id)
	}
	return repository.Registry{}, nil
}

func newTestRegistryService(repo repository.RegistryRepository) *registryService {
	return &registryService{repo: repo}
}

// ---------------------------------------------------------------------------
// CRUD tests
// ---------------------------------------------------------------------------

func TestRegistryCreate_DefaultVisibility(t *testing.T) {
	is := is.New(t)
	var capturedVis string
	svc := newTestRegistryService(&fakeRegistryRepo{
		createFn: func(_ context.Context, arg repository.CreateRegistryParams) (repository.Registry, error) {
			capturedVis = arg.Visibility
			return repository.Registry{Visibility: arg.Visibility}, nil
		},
	})

	_, err := svc.Create(context.Background(), "r", "generic", "https://r.example.com", false, nil, nil, nil, nil, "webhook", 0, nil, nil, pgtype.UUID{}, "", false)

	is.NoErr(err)
	is.Equal(capturedVis, "public") // empty string defaults to "public"
}

func TestRegistryCreate_ExplicitVisibility(t *testing.T) {
	is := is.New(t)
	var capturedVis string
	svc := newTestRegistryService(&fakeRegistryRepo{
		createFn: func(_ context.Context, arg repository.CreateRegistryParams) (repository.Registry, error) {
			capturedVis = arg.Visibility
			return repository.Registry{Visibility: arg.Visibility}, nil
		},
	})

	_, err := svc.Create(context.Background(), "r", "generic", "https://r.example.com", false, nil, nil, nil, nil, "webhook", 0, nil, nil, pgtype.UUID{}, "private", false)

	is.NoErr(err)
	is.Equal(capturedVis, "private")
}

func TestRegistryGet_InvalidUUID(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{})

	_, err := svc.Get(context.Background(), "not-a-uuid")
	is.Equal(err, ErrNotFound)
}

func TestRegistryGet_NotFound(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		getFn: func(_ context.Context, _ pgtype.UUID) (repository.Registry, error) {
			return repository.Registry{}, errors.New("no rows")
		},
	})

	_, err := svc.Get(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10")
	is.Equal(err, ErrNotFound)
}

func TestRegistryGet_Valid(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		getFn: func(_ context.Context, _ pgtype.UUID) (repository.Registry, error) {
			return repository.Registry{Name: "myreg", Type: "harbor", ScanMode: "poll"}, nil
		},
	})

	reg, err := svc.Get(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10")

	is.NoErr(err)
	is.Equal(reg.Name, "myreg")
}

func TestRegistryDelete_NotFound(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		deleteFn: func(_ context.Context, _ pgtype.UUID) (int64, error) { return 0, nil },
	})

	err := svc.Delete(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10")
	is.Equal(err, ErrNotFound)
}

func TestRegistryDelete_InvalidUUID(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{})

	err := svc.Delete(context.Background(), "bad")
	is.Equal(err, ErrNotFound)
}

func TestRegistryDelete_Valid(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		deleteFn: func(_ context.Context, _ pgtype.UUID) (int64, error) { return 1, nil },
	})

	err := svc.Delete(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10")
	is.NoErr(err)
}

func TestRegistryUpdate_DefaultVisibility(t *testing.T) {
	is := is.New(t)
	var capturedVis string
	svc := newTestRegistryService(&fakeRegistryRepo{
		updateFn: func(_ context.Context, arg repository.UpdateRegistryParams) (repository.Registry, error) {
			capturedVis = arg.Visibility
			return repository.Registry{Visibility: arg.Visibility}, nil
		},
	})

	_, err := svc.Update(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10", "r", "generic", "https://r.example.com", false, nil, true, nil, nil, nil, "webhook", 0, nil, nil, "", false)

	is.NoErr(err)
	is.Equal(capturedVis, "public")
}

// ---------------------------------------------------------------------------
// matchPatternList tests
// ---------------------------------------------------------------------------

func TestMatchPatternList_EmptyAcceptsAll(t *testing.T) {
	is := is.New(t)
	is.True(matchPatternList("anything", nil))
	is.True(matchPatternList("", nil))
	is.True(matchPatternList("foo/bar", []string{}))
}

func TestMatchPatternList_ExactMatch(t *testing.T) {
	is := is.New(t)
	is.True(matchPatternList("library/ubuntu", []string{"library/ubuntu"}))
	is.True(!matchPatternList("library/alpine", []string{"library/ubuntu"}))
}

func TestMatchPatternList_GlobMatch(t *testing.T) {
	is := is.New(t)
	is.True(matchPatternList("library/ubuntu", []string{"library/*"}))
	is.True(!matchPatternList("other/ubuntu", []string{"library/*"}))
}

func TestMatchPatternList_SkipsEmpty(t *testing.T) {
	is := is.New(t)
	// An empty pattern entry should be skipped, not match everything.
	is.True(!matchPatternList("foo", []string{"", "bar"}))
}

// ---------------------------------------------------------------------------
// matchGlob tests
// ---------------------------------------------------------------------------

func TestMatchGlob_Semver(t *testing.T) {
	is := is.New(t)
	is.True(matchGlob("semver", "1.2.3"))
	is.True(matchGlob("semver", "v1.2.3"))
	is.True(!matchGlob("semver", "latest"))
	is.True(!matchGlob("semver", "main"))
}

func TestMatchGlob_DoubleStar(t *testing.T) {
	is := is.New(t)
	is.True(matchGlob("**", "anything"))
	is.True(matchGlob("**", ""))
}

func TestMatchGlob_PrefixDoubleStarSlash(t *testing.T) {
	is := is.New(t)
	is.True(matchGlob("myrepo/**", "myrepo"))
	is.True(matchGlob("myrepo/**", "myrepo/sub"))
	is.True(matchGlob("myrepo/**", "myrepo/sub/deep"))
	is.True(!matchGlob("myrepo/**", "other"))
	is.True(!matchGlob("myrepo/**", "myrepox"))
}

func TestMatchGlob_WildcardStar(t *testing.T) {
	is := is.New(t)
	is.True(matchGlob("v*", "v1"))
	is.True(matchGlob("v*", "v1.2.3"))
	is.True(!matchGlob("v*", "1.2.3"))
}

func TestMatchGlob_Exact(t *testing.T) {
	is := is.New(t)
	is.True(matchGlob("latest", "latest"))
	is.True(!matchGlob("latest", "stable"))
}

// ---------------------------------------------------------------------------
// BuildCredentialResolver tests
// ---------------------------------------------------------------------------

// fakeListRegistryService is a minimal RegistryService that returns a fixed list.
type fakeListRegistryService struct {
	registries []Registry
}

func (f *fakeListRegistryService) List(_ context.Context, _ VisibilityFilter) ([]Registry, error) {
	return f.registries, nil
}

func (f *fakeListRegistryService) Create(_ context.Context, _, _, _ string, _ bool, _ *string, _, _, _ []string, _ string, _ int, _, _ *string, _ pgtype.UUID, _ string, _ bool) (Registry, error) {
	return Registry{}, nil
}

func (f *fakeListRegistryService) Get(_ context.Context, _ string) (Registry, error) {
	return Registry{}, ErrNotFound
}

func (f *fakeListRegistryService) Update(_ context.Context, _, _, _, _ string, _ bool, _ *string, _ bool, _, _, _ []string, _ string, _ int, _, _ *string, _ string, _ bool) (Registry, error) {
	return Registry{}, nil
}

func (f *fakeListRegistryService) SetEnabled(_ context.Context, _ string, _ bool) (Registry, error) {
	return Registry{}, nil
}

func (f *fakeListRegistryService) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeListRegistryService) ListPollable(_ context.Context) ([]Registry, error) {
	return nil, nil
}

func (f *fakeListRegistryService) MarkPolled(_ context.Context, _ string) (Registry, error) {
	return Registry{}, nil
}

func TestBuildCredentialResolver_MatchingHost(t *testing.T) {
	is := is.New(t)
	user := "admin"
	token := "secret123"
	svc := &fakeListRegistryService{
		registries: []Registry{
			{URL: "https://registry.example.com", AuthUsername: &user, AuthToken: &token},
		},
	}
	resolver := BuildCredentialResolver(svc)

	u, tk := resolver("registry.example.com")

	is.Equal(u, user)
	is.Equal(tk, token)
}

func TestBuildCredentialResolver_NoMatch(t *testing.T) {
	is := is.New(t)
	token := "secret"
	svc := &fakeListRegistryService{
		registries: []Registry{
			{URL: "https://other.example.com", AuthToken: &token},
		},
	}
	resolver := BuildCredentialResolver(svc)

	u, tk := resolver("registry.example.com")

	is.Equal(u, "")
	is.Equal(tk, "")
}

// ---------------------------------------------------------------------------
// Registry domain method tests (pure, no DB)
// ---------------------------------------------------------------------------

func TestRegistryHasAuth(t *testing.T) {
	is := is.New(t)
	token := "tok"
	empty := ""

	r := Registry{AuthToken: &token}
	is.True(r.HasAuth())

	r2 := Registry{AuthToken: &empty}
	is.True(!r2.HasAuth())

	r3 := Registry{}
	is.True(!r3.HasAuth())
}

func TestRegistryAcceptsWebhooks(t *testing.T) {
	is := is.New(t)
	is.True(Registry{ScanMode: "webhook"}.AcceptsWebhooks())
	is.True(Registry{ScanMode: "both"}.AcceptsWebhooks())
	is.True(!Registry{ScanMode: "poll"}.AcceptsWebhooks())
}

func TestRegistryNeedsPolling(t *testing.T) {
	is := is.New(t)
	is.True(Registry{ScanMode: "poll"}.NeedsPolling())
	is.True(Registry{ScanMode: "both"}.NeedsPolling())
	is.True(!Registry{ScanMode: "webhook"}.NeedsPolling())
}

func TestRegistryMatchesRepository(t *testing.T) {
	is := is.New(t)
	r := Registry{RepositoryPatterns: []string{"library/*"}}
	is.True(r.MatchesRepository("library/ubuntu"))
	is.True(!r.MatchesRepository("other/ubuntu"))
}

func TestRegistryMatchesTag(t *testing.T) {
	is := is.New(t)
	r := Registry{TagPatterns: []string{"semver"}}
	is.True(r.MatchesTag("1.2.3"))
	is.True(!r.MatchesTag("latest"))
}

func TestRegistryMatchesImage(t *testing.T) {
	is := is.New(t)
	r := Registry{
		RepositoryPatterns: []string{"library/*"},
		TagPatterns:        []string{"semver"},
	}
	is.True(r.MatchesImage("library/ubuntu", "1.2.3"))
	is.True(!r.MatchesImage("library/ubuntu", "latest"))
	is.True(!r.MatchesImage("other/ubuntu", "1.2.3"))
}

// ---------------------------------------------------------------------------
// RegistryService List / ListPollable / MarkPolled / SetEnabled tests
// ---------------------------------------------------------------------------

func TestRegistryList(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		listFn: func(_ context.Context, arg repository.ListRegistriesParams) ([]repository.Registry, error) {
			return []repository.Registry{
				{Name: "reg1", Type: "harbor", ScanMode: "webhook"},
			}, nil
		},
	})

	regs, err := svc.List(context.Background(), VisibilityFilter{IsAdmin: true})
	is.NoErr(err)
	is.Equal(len(regs), 1)
	is.Equal(regs[0].Name, "reg1")
}

func TestRegistryList_RepoError(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		listFn: func(_ context.Context, _ repository.ListRegistriesParams) ([]repository.Registry, error) {
			return nil, errors.New("db error")
		},
	})

	_, err := svc.List(context.Background(), VisibilityFilter{})
	is.True(err != nil)
}

func TestRegistryListPollable(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		listPollFn: func(_ context.Context) ([]repository.Registry, error) {
			return []repository.Registry{
				{Name: "pollable", ScanMode: "poll"},
			}, nil
		},
	})

	regs, err := svc.ListPollable(context.Background())
	is.NoErr(err)
	is.Equal(len(regs), 1)
}

func TestRegistryMarkPolled_Valid(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		markPolledFn: func(_ context.Context, _ pgtype.UUID) (repository.Registry, error) {
			return repository.Registry{Name: "polled"}, nil
		},
	})

	reg, err := svc.MarkPolled(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10")
	is.NoErr(err)
	is.Equal(reg.Name, "polled")
}

func TestRegistryMarkPolled_InvalidUUID(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{})

	_, err := svc.MarkPolled(context.Background(), "bad")
	is.Equal(err, ErrNotFound)
}

func TestRegistrySetEnabled_Valid(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{
		setEnabledFn: func(_ context.Context, arg repository.SetRegistryEnabledParams) (repository.Registry, error) {
			return repository.Registry{Name: "r", Enabled: arg.Enabled}, nil
		},
	})

	reg, err := svc.SetEnabled(context.Background(), "01020304-0506-0708-090a-0b0c0d0e0f10", true)
	is.NoErr(err)
	is.True(reg.Enabled)
}

func TestRegistrySetEnabled_InvalidUUID(t *testing.T) {
	is := is.New(t)
	svc := newTestRegistryService(&fakeRegistryRepo{})

	_, err := svc.SetEnabled(context.Background(), "bad", true)
	is.Equal(err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// BuildInsecureResolver tests
// ---------------------------------------------------------------------------

func TestBuildInsecureResolver_MatchingInsecureHost(t *testing.T) {
	is := is.New(t)
	svc := &fakeListRegistryService{
		registries: []Registry{
			{URL: "http://insecure.example.com", Insecure: true},
		},
	}
	resolver := BuildInsecureResolver(svc)

	is.True(resolver("insecure.example.com"))
}

func TestBuildInsecureResolver_SecureHost(t *testing.T) {
	is := is.New(t)
	svc := &fakeListRegistryService{
		registries: []Registry{
			{URL: "https://secure.example.com", Insecure: false},
		},
	}
	resolver := BuildInsecureResolver(svc)

	is.True(!resolver("secure.example.com"))
}

func TestBuildCredentialResolver_NoAuthToken(t *testing.T) {
	is := is.New(t)
	svc := &fakeListRegistryService{
		registries: []Registry{
			{URL: "https://registry.example.com"}, // no token
		},
	}
	resolver := BuildCredentialResolver(svc)

	u, tk := resolver("registry.example.com")

	is.Equal(u, "")
	is.Equal(tk, "")
}

// ---------------------------------------------------------------------------
// nonEmpty tests
// ---------------------------------------------------------------------------

func TestNonEmpty_FiltersEmpty(t *testing.T) {
	is := is.New(t)
	result := nonEmpty([]string{"a", "", "b", "", "c"})
	is.Equal(result, []string{"a", "b", "c"})
}

func TestNonEmpty_AllEmpty(t *testing.T) {
	is := is.New(t)
	result := nonEmpty([]string{"", ""})
	is.Equal(len(result), 0)
}

func TestNonEmpty_Nil(t *testing.T) {
	is := is.New(t)
	result := nonEmpty(nil)
	is.Equal(len(result), 0)
}

// ---------------------------------------------------------------------------
// uuidToPtr and toLicenseSummary (from search.go)
// ---------------------------------------------------------------------------

func TestUUIDToPtr_Valid(t *testing.T) {
	is := is.New(t)
	id := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	p := uuidToPtr(id)
	is.True(p != nil)
	is.True(*p != "")
}

func TestUUIDToPtr_Invalid(t *testing.T) {
	is := is.New(t)
	is.True(uuidToPtr(pgtype.UUID{}) == nil)
}

func TestToLicenseSummary(t *testing.T) {
	is := is.New(t)
	id := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	l := repository.License{
		ID:     id,
		Name:   "MIT",
		SpdxID: pgtype.Text{String: "MIT", Valid: true},
	}
	summary := toLicenseSummary(l)
	is.Equal(summary.Name, "MIT")
	is.True(summary.SpdxID != nil)
	is.Equal(*summary.SpdxID, "MIT")
}
