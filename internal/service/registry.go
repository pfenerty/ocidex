package service

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Registry is the domain model for a configured OCI registry.
type Registry struct {
	ID                 string
	Name               string
	Type               string
	URL                string
	Insecure           bool
	WebhookSecret      *string // nil = no auth required
	Enabled            bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
	RepositoryPatterns []string // glob patterns; empty = accept all
	TagPatterns        []string // glob patterns or "semver"; empty = accept all
}

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

// RegistryService manages registry configuration.
type RegistryService interface {
	Create(ctx context.Context, name, regType, url string, insecure bool, webhookSecret *string, repositoryPatterns, tagPatterns []string) (Registry, error)
	Get(ctx context.Context, id string) (Registry, error)
	List(ctx context.Context) ([]Registry, error)
	Update(ctx context.Context, id, name, regType, url string, insecure bool, webhookSecret *string, enabled bool, repositoryPatterns, tagPatterns []string) (Registry, error)
	SetEnabled(ctx context.Context, id string, enabled bool) (Registry, error)
	Delete(ctx context.Context, id string) error
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

func (s *registryService) Create(ctx context.Context, name, regType, url string, insecure bool, webhookSecret *string, repositoryPatterns, tagPatterns []string) (Registry, error) {
	r, err := s.repo.CreateRegistry(ctx, repository.CreateRegistryParams{
		Name:               name,
		Type:               regType,
		Url:                url,
		Insecure:           insecure,
		WebhookSecret:      toNullText(webhookSecret),
		RepositoryPatterns: nonEmpty(repositoryPatterns),
		TagPatterns:        nonEmpty(tagPatterns),
	})
	if err != nil {
		return Registry{}, fmt.Errorf("creating registry: %w", err)
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

func (s *registryService) List(ctx context.Context) ([]Registry, error) {
	rows, err := s.repo.ListRegistries(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing registries: %w", err)
	}
	out := make([]Registry, len(rows))
	for i, r := range rows {
		out[i] = fromRepo(r)
	}
	return out, nil
}

func (s *registryService) Update(ctx context.Context, id, name, regType, url string, insecure bool, webhookSecret *string, enabled bool, repositoryPatterns, tagPatterns []string) (Registry, error) {
	uid, err := parseRegistryUUID(id)
	if err != nil {
		return Registry{}, ErrNotFound
	}
	r, err := s.repo.UpdateRegistry(ctx, repository.UpdateRegistryParams{
		ID:                 uid,
		Name:               name,
		Type:               regType,
		Url:                url,
		Insecure:           insecure,
		WebhookSecret:      toNullText(webhookSecret),
		Enabled:            enabled,
		RepositoryPatterns: nonEmpty(repositoryPatterns),
		TagPatterns:        nonEmpty(tagPatterns),
	})
	if err != nil {
		return Registry{}, fmt.Errorf("updating registry: %w", err)
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
		ID:                 uuidToStr(r.ID),
		Name:               r.Name,
		Type:               r.Type,
		URL:                r.Url,
		Insecure:           r.Insecure,
		Enabled:            r.Enabled,
		CreatedAt:          r.CreatedAt.Time,
		UpdatedAt:          r.UpdatedAt.Time,
		RepositoryPatterns: r.RepositoryPatterns,
		TagPatterns:        r.TagPatterns,
	}
	if r.WebhookSecret.Valid {
		s := r.WebhookSecret.String
		out.WebhookSecret = &s
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
	out := ss[:0:0]
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
