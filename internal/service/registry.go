package service

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Registry is the domain model for a configured OCI registry.
type Registry struct {
	ID                  string
	Name                string
	Type                string
	URL                 string
	Insecure            bool
	WebhookSecret       *string // nil = no auth required
	Enabled             bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Repositories        []string // explicit repos to walk; empty = use catalog discovery
	RepositoryPatterns  []string // glob patterns; empty = accept all
	TagPatterns         []string // glob patterns or "semver"; empty = accept all
	ScanMode            string   // "webhook" | "poll" | "both"
	PollIntervalMinutes int
	LastPolledAt        *time.Time // nil if never polled
	AuthUsername        *string    // nil = no auth
	AuthToken           *string    // nil = no auth
	OwnerID             *string    // nil = no owner (legacy)
	Visibility          string     // "public" | "private"
	IncludeUntagged     bool       // scan untagged manifests via registry-specific APIs
	VerificationMode    string     // "none" | "public_key" | "keyless"
	TrustPublicKey      *string    // PEM-encoded EC public key; nil when mode != public_key
}

// HasAuth returns true if the registry has authentication credentials configured.
func (r Registry) HasAuth() bool { return r.AuthToken != nil && *r.AuthToken != "" }

// AcceptsWebhooks returns true if the registry should process incoming webhooks.
func (r Registry) AcceptsWebhooks() bool { return r.ScanMode == "webhook" || r.ScanMode == "both" }

// NeedsPolling returns true if the registry should be periodically polled.
func (r Registry) NeedsPolling() bool { return r.ScanMode == "poll" || r.ScanMode == "both" }

// MatchesRepository returns true if repo matches the registry's configured
// repository patterns. An empty pattern list accepts everything.
func (r Registry) MatchesRepository(repo string) bool {
	return matchPatternList(repo, r.RepositoryPatterns)
}

// MatchesTag returns true if tag matches the registry's configured tag patterns.
// An empty pattern list accepts everything.
func (r Registry) MatchesTag(tag string) bool {
	return matchPatternList(tag, r.TagPatterns)
}

// MatchesImage returns true if both repo and tag pass their respective filters.
func (r Registry) MatchesImage(repo, tag string) bool {
	return r.MatchesRepository(repo) && r.MatchesTag(tag)
}

// semverRe matches standard semver strings with optional leading "v".
var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-[A-Za-z0-9.]+)?(\+[A-Za-z0-9.]+)?$`)

// matchPatternList returns true if s matches any pattern in the list.
// Empty list means "accept all".
func matchPatternList(s string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if matchGlob(p, s) {
			return true
		}
	}
	return false
}

// matchGlob matches s against a single pattern.
//   - "semver" is a special keyword that accepts any valid semantic version.
//   - "**" matches everything.
//   - Patterns ending in "/**" match the prefix and everything beneath it.
//   - All other patterns use path.Match (supports * and ?).
func matchGlob(pattern, s string) bool {
	if pattern == "semver" {
		return semverRe.MatchString(s)
	}
	if pattern == "**" {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return s == prefix || strings.HasPrefix(s, prefix+"/")
	}
	ok, _ := path.Match(pattern, s)
	return ok
}

// HostInsecurityChecker reports whether a given hostname should be contacted
// over plain HTTP (TLS verification disabled or HTTP-only).
type HostInsecurityChecker func(ctx context.Context, host string) bool

// HostCredentialLookup returns the (username, token) pair for a hostname, or
// ("", "") when no credentials are configured for that host.
type HostCredentialLookup func(ctx context.Context, host string) (username, token string)

// registryHost strips the scheme and trailing slash from a registry URL,
// returning the bare host[:port] used for lookup.
func registryHost(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i != -1 {
		rawURL = rawURL[i+3:]
	}
	return strings.TrimSuffix(rawURL, "/")
}

const resolverCacheTTL = 30 * time.Second

// BuildInsecureHostLookup returns a HostInsecurityChecker that reports whether
// a host is configured as insecure. Results are cached for resolverCacheTTL to
// avoid a DB round-trip on every OCI pull.
func BuildInsecureHostLookup(svc RegistryService) HostInsecurityChecker {
	var (
		mu        sync.Mutex
		cache     map[string]bool
		fetchedAt time.Time
	)
	return func(ctx context.Context, host string) bool {
		mu.Lock()
		defer mu.Unlock()
		if cache == nil || time.Since(fetchedAt) > resolverCacheTTL {
			regs, err := svc.List(ctx, VisibilityFilter{IsAdmin: true})
			if err != nil {
				return false
			}
			cache = make(map[string]bool, len(regs))
			for _, r := range regs {
				cache[registryHost(r.URL)] = r.Insecure
			}
			fetchedAt = time.Now()
		}
		return cache[host]
	}
}

// BuildCredentialLookup returns a HostCredentialLookup that resolves registry
// credentials by hostname. Results are cached for resolverCacheTTL to avoid a
// DB round-trip on every OCI pull.
func BuildCredentialLookup(svc RegistryService) HostCredentialLookup {
	type creds struct{ username, token string }
	var (
		mu        sync.Mutex
		cache     map[string]creds
		fetchedAt time.Time
	)
	return func(ctx context.Context, host string) (string, string) {
		mu.Lock()
		defer mu.Unlock()
		if cache == nil || time.Since(fetchedAt) > resolverCacheTTL {
			regs, err := svc.List(ctx, VisibilityFilter{IsAdmin: true})
			if err != nil {
				return "", ""
			}
			cache = make(map[string]creds, len(regs))
			for _, r := range regs {
				if r.AuthToken == nil || *r.AuthToken == "" {
					continue
				}
				u := ""
				if r.AuthUsername != nil {
					u = *r.AuthUsername
				}
				cache[registryHost(r.URL)] = creds{u, *r.AuthToken}
			}
			fetchedAt = time.Now()
		}
		c := cache[host]
		return c.username, c.token
	}
}

// BuildTrustLookup returns a resolver that maps a registry hostname to its
// configured verification mode and PEM public key. Results are cached for
// resolverCacheTTL to avoid a DB round-trip on every enrichment.
func BuildTrustLookup(svc RegistryService) func(ctx context.Context, host string) (mode, pemKey string) {
	type trust struct{ mode, pemKey string }
	var (
		mu        sync.Mutex
		cache     map[string]trust
		fetchedAt time.Time
	)
	return func(ctx context.Context, host string) (string, string) {
		mu.Lock()
		defer mu.Unlock()
		if cache == nil || time.Since(fetchedAt) > resolverCacheTTL {
			regs, err := svc.List(ctx, VisibilityFilter{IsAdmin: true})
			if err != nil {
				return "none", ""
			}
			cache = make(map[string]trust, len(regs))
			for _, r := range regs {
				pemKey := ""
				if r.TrustPublicKey != nil {
					pemKey = *r.TrustPublicKey
				}
				cache[registryHost(r.URL)] = trust{r.VerificationMode, pemKey}
			}
			fetchedAt = time.Now()
		}
		t := cache[host]
		if t.mode == "" {
			return "none", ""
		}
		return t.mode, t.pemKey
	}
}

// VisibilityFilter controls which registries or artifacts are visible to the caller.
type VisibilityFilter struct {
	IsAdmin bool        // admin sees everything
	UserID  pgtype.UUID // authenticated user's ID (zero-value if unauthenticated)
}

// RegistryService manages registry configuration.
type RegistryService interface {
	Create(ctx context.Context, name, regType, url string, insecure bool, webhookSecret *string, repositories, repositoryPatterns, tagPatterns []string, scanMode string, pollIntervalMinutes int, authUsername, authToken *string, ownerID pgtype.UUID, visibility string, includeUntagged bool, verificationMode string, trustPublicKey *string) (Registry, error)
	Get(ctx context.Context, id string) (Registry, error)
	GetByName(ctx context.Context, name string) (Registry, error)
	List(ctx context.Context, filter VisibilityFilter) ([]Registry, error)
	ListPaged(ctx context.Context, filter VisibilityFilter, limit, offset int32) (PagedResult[Registry], error)
	Update(ctx context.Context, id, name, regType, url string, insecure bool, webhookSecret *string, enabled bool, repositories, repositoryPatterns, tagPatterns []string, scanMode string, pollIntervalMinutes int, authUsername, authToken *string, visibility string, includeUntagged bool, verificationMode string, trustPublicKey *string) (Registry, error)
	SetEnabled(ctx context.Context, id string, enabled bool) (Registry, error)
	Delete(ctx context.Context, id string) error
	ListPollable(ctx context.Context) ([]Registry, error)
	MarkPolled(ctx context.Context, id string) (Registry, error)
}

type registryService struct {
	pool *pgxpool.Pool
	repo repository.RegistryRepository
}

// NewRegistryService constructs a RegistryService.
func NewRegistryService(pool *pgxpool.Pool) RegistryService {
	return &registryService{
		pool: pool,
		repo: repository.New(pool),
	}
}

func (s *registryService) Create(ctx context.Context, name, regType, url string, insecure bool, webhookSecret *string, repositories, repositoryPatterns, tagPatterns []string, scanMode string, pollIntervalMinutes int, authUsername, authToken *string, ownerID pgtype.UUID, visibility string, includeUntagged bool, verificationMode string, trustPublicKey *string) (Registry, error) {
	if visibility == "" {
		visibility = "public"
	}
	if verificationMode == "" {
		verificationMode = "none"
	}
	r, err := s.repo.CreateRegistry(ctx, repository.CreateRegistryParams{
		Name:                name,
		Type:                regType,
		Url:                 url,
		Insecure:            insecure,
		WebhookSecret:       toNullText(webhookSecret),
		Repositories:        nonEmpty(repositories),
		RepositoryPatterns:  nonEmpty(repositoryPatterns),
		TagPatterns:         nonEmpty(tagPatterns),
		ScanMode:            scanMode,
		PollIntervalMinutes: int32(pollIntervalMinutes), //nolint:gosec // G115: poll interval is validated to fit int32
		AuthUsername:        toNullText(authUsername),
		AuthToken:           toNullText(authToken),
		OwnerID:             ownerID,
		Visibility:          visibility,
		IncludeUntagged:     includeUntagged,
		VerificationMode:    verificationMode,
		TrustPublicKey:      toNullText(trustPublicKey),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Registry{}, ErrConflict
		}
		return Registry{}, fmt.Errorf("creating registry: %w", err)
	}
	return fromRepo(r), nil
}

func (s *registryService) GetByName(ctx context.Context, name string) (Registry, error) {
	r, err := s.repo.GetRegistryByName(ctx, name)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	return fromRepo(r), nil
}

func (s *registryService) Get(ctx context.Context, id string) (Registry, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	r, err := s.repo.GetRegistry(ctx, uid)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	return fromRepo(r), nil
}

func (s *registryService) List(ctx context.Context, filter VisibilityFilter) ([]Registry, error) {
	rows, err := s.repo.ListRegistries(ctx, repository.ListRegistriesParams{
		IsAdmin: pgtype.Bool{Bool: filter.IsAdmin, Valid: true},
		UserID:  filter.UserID,
	})
	if err != nil {
		return nil, fmt.Errorf("listing registries: %w", err)
	}
	out := make([]Registry, len(rows))
	for i, r := range rows {
		out[i] = fromRepo(r)
	}
	return out, nil
}

func (s *registryService) ListPaged(ctx context.Context, filter VisibilityFilter, limit, offset int32) (PagedResult[Registry], error) {
	rows, err := s.repo.ListRegistriesPaged(ctx, repository.ListRegistriesPagedParams{
		IsAdmin:   pgtype.Bool{Bool: filter.IsAdmin, Valid: true},
		UserID:    filter.UserID,
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[Registry]{}, fmt.Errorf("listing registries: %w", err)
	}
	var total int64
	if len(rows) > 0 {
		total = rows[0].TotalCount
	}
	out := make([]Registry, len(rows))
	for i, r := range rows {
		out[i] = fromRepo(repository.Registry{
			ID:                  r.ID,
			Name:                r.Name,
			Type:                r.Type,
			Url:                 r.Url,
			Insecure:            r.Insecure,
			WebhookSecret:       r.WebhookSecret,
			Enabled:             r.Enabled,
			CreatedAt:           r.CreatedAt,
			UpdatedAt:           r.UpdatedAt,
			RepositoryPatterns:  r.RepositoryPatterns,
			TagPatterns:         r.TagPatterns,
			ScanMode:            r.ScanMode,
			PollIntervalMinutes: r.PollIntervalMinutes,
			LastPolledAt:        r.LastPolledAt,
			Repositories:        r.Repositories,
			AuthUsername:        r.AuthUsername,
			AuthToken:           r.AuthToken,
			OwnerID:             r.OwnerID,
			Visibility:          r.Visibility,
			IncludeUntagged:     r.IncludeUntagged,
			VerificationMode:    r.VerificationMode,
			TrustPublicKey:      r.TrustPublicKey,
		})
	}
	return PagedResult[Registry]{Data: out, Total: total, Limit: limit, Offset: offset}, nil
}

func (s *registryService) Update(ctx context.Context, id, name, regType, url string, insecure bool, webhookSecret *string, enabled bool, repositories, repositoryPatterns, tagPatterns []string, scanMode string, pollIntervalMinutes int, authUsername, authToken *string, visibility string, includeUntagged bool, verificationMode string, trustPublicKey *string) (Registry, error) {
	if visibility == "" {
		visibility = "public"
	}
	if verificationMode == "" {
		verificationMode = "none"
	}
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	// Read existing to preserve trust columns not yet exposed (TrustIdentity, TrustIssuer).
	existing, err := s.repo.GetRegistry(ctx, uid)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	r, err := s.repo.UpdateRegistry(ctx, repository.UpdateRegistryParams{
		ID:                  uid,
		Name:                name,
		Type:                regType,
		Url:                 url,
		Insecure:            insecure,
		WebhookSecret:       toNullText(webhookSecret),
		Enabled:             enabled,
		Repositories:        nonEmpty(repositories),
		RepositoryPatterns:  nonEmpty(repositoryPatterns),
		TagPatterns:         nonEmpty(tagPatterns),
		ScanMode:            scanMode,
		PollIntervalMinutes: int32(pollIntervalMinutes), //nolint:gosec // G115: poll interval is validated to fit int32
		AuthUsername:        toNullText(authUsername),
		AuthToken:           toNullText(authToken),
		Visibility:          visibility,
		IncludeUntagged:     includeUntagged,
		VerificationMode:    verificationMode,
		TrustPublicKey:      toNullText(trustPublicKey),
		TrustIdentity:       existing.TrustIdentity,
		TrustIssuer:         existing.TrustIssuer,
	})
	if err != nil {
		return Registry{}, fmt.Errorf("updating registry: %w", err)
	}
	return fromRepo(r), nil
}

func (s *registryService) ListPollable(ctx context.Context) ([]Registry, error) {
	rows, err := s.repo.ListPollableRegistries(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pollable registries: %w", err)
	}
	out := make([]Registry, len(rows))
	for i, r := range rows {
		out[i] = fromRepo(r)
	}
	return out, nil
}

func (s *registryService) MarkPolled(ctx context.Context, id string) (Registry, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	r, err := s.repo.UpdateRegistryLastPolled(ctx, uid)
	if err != nil {
		return Registry{}, fmt.Errorf("marking registry polled: %w", err)
	}
	return fromRepo(r), nil
}

func (s *registryService) SetEnabled(ctx context.Context, id string, enabled bool) (Registry, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	r, err := s.repo.SetRegistryEnabled(ctx, repository.SetRegistryEnabledParams{
		ID:      uid,
		Enabled: enabled,
	})
	if err != nil {
		return Registry{}, fmt.Errorf("setting registry enabled: %w", err)
	}
	return fromRepo(r), nil
}

func (s *registryService) Delete(ctx context.Context, id string) error {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return ErrNotFound
	}
	n, err := s.repo.DeleteRegistry(ctx, uid)
	if err != nil {
		return fmt.Errorf("deleting registry: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func fromRepo(r repository.Registry) Registry {
	out := Registry{
		ID:                  uuidToStr(r.ID),
		Name:                r.Name,
		Type:                r.Type,
		URL:                 r.Url,
		Insecure:            r.Insecure,
		Enabled:             r.Enabled,
		CreatedAt:           r.CreatedAt.Time,
		UpdatedAt:           r.UpdatedAt.Time,
		Repositories:        r.Repositories,
		RepositoryPatterns:  r.RepositoryPatterns,
		TagPatterns:         r.TagPatterns,
		ScanMode:            r.ScanMode,
		PollIntervalMinutes: int(r.PollIntervalMinutes),
		Visibility:          r.Visibility,
		IncludeUntagged:     r.IncludeUntagged,
	}
	if r.WebhookSecret.Valid {
		s := r.WebhookSecret.String
		out.WebhookSecret = &s
	}
	if r.LastPolledAt.Valid {
		t := r.LastPolledAt.Time
		out.LastPolledAt = &t
	}
	if r.AuthUsername.Valid {
		s := r.AuthUsername.String
		out.AuthUsername = &s
	}
	if r.AuthToken.Valid {
		s := r.AuthToken.String
		out.AuthToken = &s
	}
	if r.OwnerID.Valid {
		s := uuidToStr(r.OwnerID)
		out.OwnerID = &s
	}
	out.VerificationMode = r.VerificationMode
	if r.TrustPublicKey.Valid {
		s := r.TrustPublicKey.String
		out.TrustPublicKey = &s
	}
	return out
}

func toNullText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// nonEmpty filters out empty strings from a slice.
func nonEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseRegistryUUID(s string) (pgtype.UUID, error) {
	var id pgtype.UUID
	if err := id.Scan(s); err != nil || !id.Valid {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid: %s", s)
	}
	return id, nil
}

func uuidToStr(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
