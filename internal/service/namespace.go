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
//
// There is no OwnerID. Ownership was never transferable through this path — the
// handler says so and only ever read the existing owner back and wrote it
// straight out again — and with ownership in namespace_member (ocidex-y0hg.4)
// there is nothing to carry forward. Transferring ownership is member
// management.
type UpdateNamespaceParams struct {
	ID         string
	Name       string
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
		Name:        params.Name,
		OwnerUserID: params.OwnerID,
		Visibility:  visibility,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Namespace{}, ErrConflict
		}
		return Namespace{}, fmt.Errorf("creating namespace: %w", err)
	}
	return namespaceFromRepo(repository.Namespace{
		ID:         ns.ID,
		Name:       ns.Name,
		Visibility: ns.Visibility,
		CreatedAt:  ns.CreatedAt,
		UpdatedAt:  ns.UpdatedAt,
	}, ns.OwnerID), nil
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
	return namespaceFromRepo(ns.Namespace, ns.OwnerID), nil
}

func (s *namespaceService) GetByName(ctx context.Context, name string) (Namespace, error) {
	ns, err := s.repo.GetNamespaceByName(ctx, name)
	if err != nil {
		return Namespace{}, ErrNotFound
	}
	return namespaceFromRepo(ns.Namespace, ns.OwnerID), nil
}

func (s *namespaceService) List(ctx context.Context, filter VisibilityFilter) ([]Namespace, error) {
	rows, err := s.repo.ListNamespaces(ctx, repository.ListNamespacesParams{
		IsAdmin:   filter.adminFlag(),
		UserID:    filter.UserID,
		OwnedOnly: filter.ownedFlag(),
	})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	out := make([]Namespace, len(rows))
	for i, ns := range rows {
		out[i] = namespaceFromRepo(ns.Namespace, ns.OwnerID)
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
	visibility := params.Visibility
	if visibility == "" {
		visibility = existing.Namespace.Visibility
	}
	name := params.Name
	if name == "" {
		name = existing.Namespace.Name
	}
	ns, err := s.repo.UpdateNamespace(ctx, repository.UpdateNamespaceParams{
		ID:         uid,
		Name:       name,
		Visibility: visibility,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Namespace{}, ErrConflict
		}
		return Namespace{}, fmt.Errorf("updating namespace: %w", err)
	}
	return namespaceFromRepo(repository.Namespace{
		ID:         ns.ID,
		Name:       ns.Name,
		Visibility: ns.Visibility,
		CreatedAt:  ns.CreatedAt,
		UpdatedAt:  ns.UpdatedAt,
	}, ns.OwnerID), nil
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

// namespaceFromRepo renders a namespace row plus its owner. The owner arrives
// separately because it is no longer a column: every namespace-returning query
// projects it with namespace_owner(), and sqlc gives each of them its own row
// type. Passing it in keeps one renderer rather than one per query shape.
func namespaceFromRepo(ns repository.Namespace, ownerID pgtype.UUID) Namespace {
	out := Namespace{
		ID:         uuidToStr(ns.ID),
		Name:       ns.Name,
		OwnerID:    uuidToPtr(ownerID),
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
