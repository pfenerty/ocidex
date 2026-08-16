package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Source kinds. An OCI registry source has a matching registry row carrying
// its pull config and trust policy; an upload source has none, which is what
// makes registry-shaped enrichment inapplicable to it (ADR-039).
const (
	SourceKindOCIRegistry = "oci_registry"
	SourceKindUpload      = "upload"
)

// Source is the channel an SBOM arrived through (ADR-039). It carries no
// ownership of its own: visibility is always resolved through its namespace.
type Source struct {
	ID            string
	NamespaceID   string
	NamespaceName string // populated by List; empty elsewhere
	Kind          string // "oci_registry" | "upload"
	Name          string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CreateSourceParams holds the parameters for creating a source.
type CreateSourceParams struct {
	NamespaceID string
	Kind        string // defaults to "upload" when empty
	Name        string
}

// UpdateSourceParams holds the parameters for renaming a source. Kind is
// immutable: changing it would strand or orphan the registry subtype row.
type UpdateSourceParams struct {
	ID   string
	Name string
}

// SourceService manages ingest channels within a namespace.
type SourceService interface {
	Create(ctx context.Context, params CreateSourceParams) (Source, error)
	Get(ctx context.Context, id string) (Source, error)
	GetByName(ctx context.Context, namespaceID, name string) (Source, error)
	ListByNamespace(ctx context.Context, namespaceID string) ([]Source, error)
	List(ctx context.Context, filter VisibilityFilter) ([]Source, error)
	Update(ctx context.Context, params UpdateSourceParams) (Source, error)
	Delete(ctx context.Context, id string) error
}

type sourceService struct {
	repo repository.SourceRepository
}

// NewSourceService constructs a SourceService.
func NewSourceService(pool *pgxpool.Pool) SourceService {
	return &sourceService{repo: repository.New(pool)}
}

func (s *sourceService) Create(ctx context.Context, params CreateSourceParams) (Source, error) {
	nsID, err := parseUUID(params.NamespaceID)
	if err != nil {
		return Source{}, ErrNotFound
	}
	kind := params.Kind
	if kind == "" {
		kind = SourceKindUpload
	}
	src, err := s.repo.CreateSource(ctx, repository.CreateSourceParams{
		NamespaceID: nsID,
		Kind:        kind,
		Name:        params.Name,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Source{}, ErrConflict
		}
		return Source{}, fmt.Errorf("creating source: %w", err)
	}
	return sourceFromRepo(src), nil
}

func (s *sourceService) Get(ctx context.Context, id string) (Source, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Source{}, ErrNotFound
	}
	src, err := s.repo.GetSource(ctx, uid)
	if err != nil {
		return Source{}, ErrNotFound
	}
	return sourceFromRepo(src), nil
}

func (s *sourceService) GetByName(ctx context.Context, namespaceID, name string) (Source, error) {
	nsID, err := parseUUID(namespaceID)
	if err != nil {
		return Source{}, ErrNotFound
	}
	src, err := s.repo.GetSourceByName(ctx, repository.GetSourceByNameParams{
		NamespaceID: nsID,
		Name:        name,
	})
	if err != nil {
		return Source{}, ErrNotFound
	}
	return sourceFromRepo(src), nil
}

func (s *sourceService) ListByNamespace(ctx context.Context, namespaceID string) ([]Source, error) {
	nsID, err := parseUUID(namespaceID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListSourcesByNamespace(ctx, nsID)
	if err != nil {
		return nil, fmt.Errorf("listing sources: %w", err)
	}
	out := make([]Source, len(rows))
	for i, src := range rows {
		out[i] = sourceFromRepo(src)
	}
	return out, nil
}

func (s *sourceService) List(ctx context.Context, filter VisibilityFilter) ([]Source, error) {
	rows, err := s.repo.ListSources(ctx, repository.ListSourcesParams{
		IsAdmin:   filter.adminFlag(),
		UserID:    filter.UserID,
		OwnedOnly: filter.ownedFlag(),
	})
	if err != nil {
		return nil, fmt.Errorf("listing sources: %w", err)
	}
	out := make([]Source, len(rows))
	for i, r := range rows {
		src := sourceFromRepo(r.Source)
		src.NamespaceName = r.NamespaceName
		out[i] = src
	}
	return out, nil
}

func (s *sourceService) Update(ctx context.Context, params UpdateSourceParams) (Source, error) {
	uid, err := parseUUID(params.ID)
	if err != nil {
		return Source{}, ErrNotFound
	}
	src, err := s.repo.UpdateSource(ctx, repository.UpdateSourceParams{
		ID:   uid,
		Name: params.Name,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Source{}, ErrConflict
		}
		return Source{}, fmt.Errorf("updating source: %w", err)
	}
	return sourceFromRepo(src), nil
}

// Delete removes a source, cascading to its registry subtype row. The owning
// namespace and its SBOMs survive; the SBOMs only lose source_id.
func (s *sourceService) Delete(ctx context.Context, id string) error {
	uid, err := parseUUID(id)
	if err != nil {
		return ErrNotFound
	}
	n, err := s.repo.DeleteSource(ctx, uid)
	if err != nil {
		return fmt.Errorf("deleting source: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func sourceFromRepo(src repository.Source) Source {
	out := Source{
		ID:          uuidToStr(src.ID),
		NamespaceID: uuidToStr(src.NamespaceID),
		Kind:        src.Kind,
		Name:        src.Name,
	}
	if src.CreatedAt.Valid {
		out.CreatedAt = src.CreatedAt.Time
	}
	if src.UpdatedAt.Valid {
		out.UpdatedAt = src.UpdatedAt.Time
	}
	return out
}
