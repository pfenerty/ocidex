package service

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/trust"
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
	TrustIdentity       *string    // regex matched against the Fulcio cert SAN; nil when mode != keyless
	TrustIssuer         *string    // exact OIDC issuer URL; nil when mode != keyless
	ManagedBy           *string    // external owner of this config, e.g. "kubernetes"; nil = managed here
	ManagedRef          *string    // identifier within that system, e.g. "<namespace>/<name>"
}

// IsManaged reports whether an external controller owns this registry's config
// and will reconcile its own spec back over any edit made here.
func (r Registry) IsManaged() bool { return r.ManagedBy != nil && *r.ManagedBy != "" }

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

// BuildTrustLookup returns a resolver that maps a registry ID to its
// configured verification settings. Results are cached for resolverCacheTTL
// to avoid a DB round-trip on every enrichment. host is used only as a
// fallback for callers that cannot supply a registry ID; since multiple
// registry rows may share a host (per-owner visibility, ADR-025), the
// host-keyed fallback defaults to "none" rather than guessing among them.
func BuildTrustLookup(svc RegistryService) func(ctx context.Context, registryID pgtype.UUID, host string) trust.Config {
	var (
		mu        sync.Mutex
		byID      map[string]trust.Config
		fetchedAt time.Time
	)
	return func(ctx context.Context, registryID pgtype.UUID, host string) trust.Config {
		mu.Lock()
		defer mu.Unlock()
		if byID == nil || time.Since(fetchedAt) > resolverCacheTTL {
			regs, err := svc.List(ctx, VisibilityFilter{IsAdmin: true})
			if err != nil {
				return trust.Config{Mode: trust.ModeNone}
			}
			byID = make(map[string]trust.Config, len(regs))
			for _, r := range regs {
				cfg := trust.Config{Mode: r.VerificationMode}
				if r.TrustPublicKey != nil {
					cfg.PublicKeyPEM = *r.TrustPublicKey
				}
				if r.TrustIdentity != nil {
					cfg.Identity = *r.TrustIdentity
				}
				if r.TrustIssuer != nil {
					cfg.Issuer = *r.TrustIssuer
				}
				byID[r.ID] = cfg
			}
			fetchedAt = time.Now()
		}
		if id := uuidToStr(registryID); id != "" {
			if cfg, ok := byID[id]; ok && cfg.Mode != "" {
				return cfg
			}
		}
		return trust.Config{Mode: trust.ModeNone}
	}
}

// VisibilityFilter controls which registries or artifacts are visible to the caller.
type VisibilityFilter struct {
	IsAdmin bool        // admin sees everything
	UserID  pgtype.UUID // authenticated user's ID (zero-value if unauthenticated)
}

// CreateRegistryParams holds the parameters for creating a new registry.
type CreateRegistryParams struct {
	Name                string
	Type                string
	URL                 string
	Insecure            bool
	WebhookSecret       *string
	Repositories        []string
	RepositoryPatterns  []string
	TagPatterns         []string
	ScanMode            string
	PollIntervalMinutes int
	AuthUsername        *string
	AuthToken           *string
	OwnerID             pgtype.UUID
	Visibility          string
	IncludeUntagged     bool
	VerificationMode    string
	TrustPublicKey      *string
	TrustIdentity       *string
	TrustIssuer         *string
	ManagedBy           *string
	ManagedRef          *string

	// Namespace is the name of the namespace to create the registry in. Empty
	// means "give it a namespace of its own named after it", the pre-ADR-039
	// shape. The operator sets this from the CR's K8s namespace so every
	// OCIRegistry in a K8s namespace shares one OCIDex tenancy boundary.
	// A namespace named here is created on first use.
	Namespace string
}

// UpdateRegistryParams holds the parameters for updating an existing registry.
//
// VerificationMode (when empty), TrustPublicKey/TrustIdentity/TrustIssuer and
// ManagedBy/ManagedRef (when nil) are preserved from the existing registry
// rather than wiped, so any caller that omits them — the HTTP API, an operator
// reconciler, a CLI, a test — can't accidentally erase provenance verification
// config or the marker saying who owns the registry.
type UpdateRegistryParams struct {
	ID                  string
	Name                string
	Type                string
	URL                 string
	Insecure            bool
	WebhookSecret       *string
	Enabled             bool
	Repositories        []string
	RepositoryPatterns  []string
	TagPatterns         []string
	ScanMode            string
	PollIntervalMinutes int
	AuthUsername        *string
	AuthToken           *string
	Visibility          string
	IncludeUntagged     bool
	VerificationMode    string
	TrustPublicKey      *string
	TrustIdentity       *string
	TrustIssuer         *string
	ManagedBy           *string
	ManagedRef          *string
}

// RegistryService manages registry configuration.
type RegistryService interface {
	Create(ctx context.Context, params CreateRegistryParams) (Registry, error)
	Get(ctx context.Context, id string) (Registry, error)
	GetByName(ctx context.Context, name string) (Registry, error)
	List(ctx context.Context, filter VisibilityFilter) ([]Registry, error)
	ListPaged(ctx context.Context, filter VisibilityFilter, limit, offset int32) (PagedResult[Registry], error)
	Update(ctx context.Context, params UpdateRegistryParams) (Registry, error)
	SetEnabled(ctx context.Context, id string, enabled bool) (Registry, error)
	Delete(ctx context.Context, id string) error
	ListPollable(ctx context.Context) ([]Registry, error)
	MarkPolled(ctx context.Context, id string) (Registry, error)
	TrustSummary(ctx context.Context) ([]RegistryTrustCount, error)
}

// RegistryTrustCount is a per-registry, per-signing-status artifact count,
// derived from each artifact's most recent SBOM via the signing_status() SQL
// function (see ocidex-82g.3).
type RegistryTrustCount struct {
	RegistryID    string `json:"registryId"`
	SigningStatus string `json:"signingStatus"`
	Count         int64  `json:"count"`
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

func (s *registryService) Create(ctx context.Context, params CreateRegistryParams) (Registry, error) {
	visibility := params.Visibility
	if visibility == "" {
		visibility = "public"
	}
	verificationMode := params.VerificationMode
	if verificationMode == "" {
		verificationMode = "none"
	}
	namespaceID, err := s.resolveNamespace(ctx, params, visibility)
	if err != nil {
		return Registry{}, err
	}
	r, err := s.repo.CreateRegistry(ctx, repository.CreateRegistryParams{
		NamespaceID:         namespaceID,
		Name:                params.Name,
		Type:                params.Type,
		Url:                 params.URL,
		Insecure:            params.Insecure,
		WebhookSecret:       toNullText(params.WebhookSecret),
		Repositories:        nonEmpty(params.Repositories),
		RepositoryPatterns:  nonEmpty(params.RepositoryPatterns),
		TagPatterns:         nonEmpty(params.TagPatterns),
		ScanMode:            params.ScanMode,
		PollIntervalMinutes: int32(params.PollIntervalMinutes), //nolint:gosec // G115: poll interval is validated to fit int32
		AuthUsername:        toNullText(params.AuthUsername),
		AuthToken:           toNullText(params.AuthToken),
		OwnerID:             params.OwnerID,
		Visibility:          visibility,
		IncludeUntagged:     params.IncludeUntagged,
		VerificationMode:    verificationMode,
		TrustPublicKey:      toNullText(params.TrustPublicKey),
		TrustIdentity:       toNullText(params.TrustIdentity),
		TrustIssuer:         toNullText(params.TrustIssuer),
		ManagedBy:           toNullText(params.ManagedBy),
		ManagedRef:          toNullText(params.ManagedRef),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Registry{}, ErrConflict
		}
		return Registry{}, fmt.Errorf("creating registry: %w", err)
	}
	return fromRepo(registryComposite{
		reg:        r,
		name:       params.Name,
		ownerID:    params.OwnerID,
		visibility: visibility,
	}), nil
}

// resolveNamespace turns params.Namespace into the id CreateRegistry should
// place the source under. An empty name yields an invalid (NULL) UUID, which
// tells the query to mint a namespace of the registry's own. A named namespace
// is looked up and created on first use — the operator reconciles many
// OCIRegistry CRs into one K8s namespace and cannot order their creation.
func (s *registryService) resolveNamespace(ctx context.Context, params CreateRegistryParams, visibility string) (pgtype.UUID, error) {
	if params.Namespace == "" {
		return pgtype.UUID{}, nil
	}
	ns, err := s.repo.GetNamespaceByName(ctx, params.Namespace)
	if err == nil {
		return ns.ID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return pgtype.UUID{}, fmt.Errorf("looking up namespace %q: %w", params.Namespace, err)
	}
	created, err := s.repo.CreateNamespace(ctx, repository.CreateNamespaceParams{
		Name:       params.Namespace,
		OwnerID:    params.OwnerID,
		Visibility: visibility,
	})
	if err != nil {
		// A concurrent reconcile won the race; re-read rather than fail.
		if isUniqueViolation(err) {
			ns, getErr := s.repo.GetNamespaceByName(ctx, params.Namespace)
			if getErr == nil {
				return ns.ID, nil
			}
		}
		return pgtype.UUID{}, fmt.Errorf("creating namespace %q: %w", params.Namespace, err)
	}
	return created.ID, nil
}

func (s *registryService) GetByName(ctx context.Context, name string) (Registry, error) {
	r, err := s.repo.GetRegistryByName(ctx, name)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	return fromRepo(registryComposite{
		reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
	}), nil
}

func (s *registryService) Get(ctx context.Context, id string) (Registry, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	r, err := s.repo.GetRegistry(ctx, uid)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	return fromRepo(registryComposite{
		reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
	}), nil
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
		out[i] = fromRepo(registryComposite{
			reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
		})
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
		out[i] = fromRepo(registryComposite{
			reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
		})
	}
	return PagedResult[Registry]{Data: out, Total: total, Limit: limit, Offset: offset}, nil
}

func (s *registryService) Update(ctx context.Context, params UpdateRegistryParams) (Registry, error) {
	uid, err := parseUUID(params.ID)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	existingRow, err := s.repo.GetRegistry(ctx, uid)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	existing := fromRepo(registryComposite{
		reg:        existingRow.Registry,
		name:       existingRow.Name,
		ownerID:    existingRow.OwnerID,
		visibility: existingRow.Visibility,
	})

	visibility := params.Visibility
	if visibility == "" {
		visibility = "public"
	}
	verificationMode := params.VerificationMode
	if verificationMode == "" {
		verificationMode = existing.VerificationMode
	}
	if verificationMode == "" {
		verificationMode = "none"
	}
	trustPublicKey := params.TrustPublicKey
	if trustPublicKey == nil {
		trustPublicKey = existing.TrustPublicKey
	}
	trustIdentity := params.TrustIdentity
	if trustIdentity == nil {
		trustIdentity = existing.TrustIdentity
	}
	trustIssuer := params.TrustIssuer
	if trustIssuer == nil {
		trustIssuer = existing.TrustIssuer
	}
	// The UI's PATCH doesn't carry the ownership marker, so preserving it here is
	// what keeps a UI edit from silently un-marking an operator-owned registry.
	managedBy := params.ManagedBy
	if managedBy == nil {
		managedBy = existing.ManagedBy
	}
	managedRef := params.ManagedRef
	if managedRef == nil {
		managedRef = existing.ManagedRef
	}

	r, err := s.repo.UpdateRegistry(ctx, repository.UpdateRegistryParams{
		ID:                  uid,
		Name:                params.Name,
		Type:                params.Type,
		Url:                 params.URL,
		Insecure:            params.Insecure,
		WebhookSecret:       toNullText(params.WebhookSecret),
		Enabled:             params.Enabled,
		Repositories:        nonEmpty(params.Repositories),
		RepositoryPatterns:  nonEmpty(params.RepositoryPatterns),
		TagPatterns:         nonEmpty(params.TagPatterns),
		ScanMode:            params.ScanMode,
		PollIntervalMinutes: int32(params.PollIntervalMinutes), //nolint:gosec // G115: poll interval is validated to fit int32
		AuthUsername:        toNullText(params.AuthUsername),
		AuthToken:           toNullText(params.AuthToken),
		Visibility:          visibility,
		IncludeUntagged:     params.IncludeUntagged,
		VerificationMode:    verificationMode,
		TrustPublicKey:      toNullText(trustPublicKey),
		TrustIdentity:       toNullText(trustIdentity),
		TrustIssuer:         toNullText(trustIssuer),
		ManagedBy:           toNullText(managedBy),
		ManagedRef:          toNullText(managedRef),
	})
	if err != nil {
		return Registry{}, fmt.Errorf("updating registry: %w", err)
	}
	return fromRepo(registryComposite{
		reg:        r,
		name:       params.Name,
		ownerID:    existingRow.OwnerID,
		visibility: visibility,
	}), nil
}

func (s *registryService) ListPollable(ctx context.Context) ([]Registry, error) {
	rows, err := s.repo.ListPollableRegistries(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pollable registries: %w", err)
	}
	out := make([]Registry, len(rows))
	for i, r := range rows {
		out[i] = fromRepo(registryComposite{
			reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
		})
	}
	return out, nil
}

func (s *registryService) MarkPolled(ctx context.Context, id string) (Registry, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	if _, err := s.repo.UpdateRegistryLastPolled(ctx, uid); err != nil {
		return Registry{}, fmt.Errorf("marking registry polled: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *registryService) SetEnabled(ctx context.Context, id string, enabled bool) (Registry, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	_, err = s.repo.SetRegistryEnabled(ctx, repository.SetRegistryEnabledParams{
		ID:      uid,
		Enabled: enabled,
	})
	if err != nil {
		return Registry{}, fmt.Errorf("setting registry enabled: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *registryService) Delete(ctx context.Context, id string) error {
	uid, err := parseUUID(id)
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

func (s *registryService) TrustSummary(ctx context.Context) ([]RegistryTrustCount, error) {
	rows, err := s.repo.ListRegistryTrustSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing registry trust summary: %w", err)
	}
	out := make([]RegistryTrustCount, len(rows))
	for i, r := range rows {
		out[i] = RegistryTrustCount{
			RegistryID:    uuidToStr(r.RegistryID),
			SigningStatus: r.SigningStatus,
			Count:         r.ArtifactCount,
		}
	}
	return out, nil
}

// registryComposite pairs the OCI-config row with the identity and ownership
// fields ADR-039 moved onto namespace. sqlc emits a distinct Row type per joined
// query, so each read path adapts into this one shape before mapping.
type registryComposite struct {
	reg        repository.Registry
	name       string
	ownerID    pgtype.UUID
	visibility string
}

func fromRepo(c registryComposite) Registry {
	r := c.reg
	out := Registry{
		ID:                  uuidToStr(r.ID),
		Name:                c.name,
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
		Visibility:          c.visibility,
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
	if c.ownerID.Valid {
		s := uuidToStr(c.ownerID)
		out.OwnerID = &s
	}
	out.VerificationMode = r.VerificationMode
	if r.TrustPublicKey.Valid {
		s := r.TrustPublicKey.String
		out.TrustPublicKey = &s
	}
	if r.TrustIdentity.Valid {
		s := r.TrustIdentity.String
		out.TrustIdentity = &s
	}
	if r.TrustIssuer.Valid {
		s := r.TrustIssuer.String
		out.TrustIssuer = &s
	}
	if r.ManagedBy.Valid {
		s := r.ManagedBy.String
		out.ManagedBy = &s
	}
	if r.ManagedRef.Valid {
		s := r.ManagedRef.String
		out.ManagedRef = &s
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

func parseUUID(s string) (pgtype.UUID, error) {
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
