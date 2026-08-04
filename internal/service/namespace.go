package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Namespace is the authorization anchor (ADR-039). Ownership and visibility
// live here and nowhere else: a source says how an SBOM arrived, a registry
// says how to pull it, but who may see it is decided here.
type Namespace struct {
	ID         string
	Name       string
	OwnerID    *string // nil = unowned
	Visibility string  // "public" | "private"
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CreateNamespaceParams holds the parameters for creating a namespace.
type CreateNamespaceParams struct {
	Name       string
	OwnerID    pgtype.UUID
	Visibility string // defaults to "private" when empty
}

// UpdateNamespaceParams holds the parameters for updating a namespace.
// OwnerID is preserved when the zero value is passed, so a caller that only
// wants to rename or re-scope a namespace cannot accidentally orphan it.
type UpdateNamespaceParams struct {
	ID         string
	Name       string
	OwnerID    pgtype.UUID
	Visibility string
}

// NamespaceService manages namespaces.
type NamespaceService interface {
	Create(ctx context.Context, params CreateNamespaceParams) (Namespace, error)
	Get(ctx context.Context, id string) (Namespace, error)
	GetByName(ctx context.Context, name string) (Namespace, error)
	List(ctx context.Context, filter VisibilityFilter) ([]Namespace, error)
	Update(ctx context.Context, params UpdateNamespaceParams) (Namespace, error)
	Delete(ctx context.Context, id string) error
}

type namespaceService struct {
	repo repository.NamespaceRepository
}

// NewNamespaceService constructs a NamespaceService.
func NewNamespaceService(pool *pgxpool.Pool) NamespaceService {
	return &namespaceService{repo: repository.New(pool)}
}

func (s *namespaceService) Create(ctx context.Context, params CreateNamespaceParams) (Namespace, error) {
	visibility := params.Visibility
	if visibility == "" {
		visibility = "private"
	}
	ns, err := s.repo.CreateNamespace(ctx, repository.CreateNamespaceParams{
		Name:       params.Name,
		OwnerID:    params.OwnerID,
		Visibility: visibility,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Namespace{}, ErrConflict
		}
		return Namespace{}, fmt.Errorf("creating namespace: %w", err)
	}
	return namespaceFromRepo(ns), nil
}

func (s *namespaceService) Get(ctx context.Context, id string) (Namespace, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Namespace{}, ErrNotFound
	}
	ns, err := s.repo.GetNamespace(ctx, uid)
	if err != nil {
		return Namespace{}, ErrNotFound
	}
	return namespaceFromRepo(ns), nil
}

func (s *namespaceService) GetByName(ctx context.Context, name string) (Namespace, error) {
	ns, err := s.repo.GetNamespaceByName(ctx, name)
	if err != nil {
		return Namespace{}, ErrNotFound
	}
	return namespaceFromRepo(ns), nil
}

func (s *namespaceService) List(ctx context.Context, filter VisibilityFilter) ([]Namespace, error) {
	rows, err := s.repo.ListNamespaces(ctx, repository.ListNamespacesParams{
		IsAdmin: pgtype.Bool{Bool: filter.IsAdmin, Valid: true},
		UserID:  filter.UserID,
	})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	out := make([]Namespace, len(rows))
	for i, ns := range rows {
		out[i] = namespaceFromRepo(ns)
	}
	return out, nil
}

func (s *namespaceService) Update(ctx context.Context, params UpdateNamespaceParams) (Namespace, error) {
	uid, err := parseUUID(params.ID)
	if err != nil {
		return Namespace{}, ErrNotFound
	}
	existing, err := s.repo.GetNamespace(ctx, uid)
	if err != nil {
		return Namespace{}, ErrNotFound
	}
	ownerID := params.OwnerID
	if !ownerID.Valid {
		ownerID = existing.OwnerID
	}
	visibility := params.Visibility
	if visibility == "" {
		visibility = existing.Visibility
	}
	name := params.Name
	if name == "" {
		name = existing.Name
	}
	ns, err := s.repo.UpdateNamespace(ctx, repository.UpdateNamespaceParams{
		ID:         uid,
		Name:       name,
		OwnerID:    ownerID,
		Visibility: visibility,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Namespace{}, ErrConflict
		}
		return Namespace{}, fmt.Errorf("updating namespace: %w", err)
	}
	return namespaceFromRepo(ns), nil
}

// Delete removes a namespace. Sources, SBOMs and rollup rows beneath it cascade
// away with it — a namespace is the tenancy boundary, so this is a tenant-level
// delete, not a config tidy-up.
func (s *namespaceService) Delete(ctx context.Context, id string) error {
	uid, err := parseUUID(id)
	if err != nil {
		return ErrNotFound
	}
	n, err := s.repo.DeleteNamespace(ctx, uid)
	if err != nil {
		return fmt.Errorf("deleting namespace: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func namespaceFromRepo(ns repository.Namespace) Namespace {
	out := Namespace{
		ID:         uuidToStr(ns.ID),
		Name:       ns.Name,
		OwnerID:    uuidToPtr(ns.OwnerID),
		Visibility: ns.Visibility,
	}
	if ns.CreatedAt.Valid {
		out.CreatedAt = ns.CreatedAt.Time
	}
	if ns.UpdatedAt.Valid {
		out.UpdatedAt = ns.UpdatedAt.Time
	}
	return out
}
