package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/repository"
)

// NamespaceMember is one (user, role) pair in a namespace. The namespace is the
// team (ADR-046); this is a seat at it.
type NamespaceMember struct {
	NamespaceID string
	UserID      string
	Role        string
	CreatedAt   time.Time
}

// SetNamespaceMemberParams holds the parameters for adding a member or changing
// an existing member's role. The two are one operation because the endpoint is
// a PUT: the caller states what the membership should be, not how it got there.
type SetNamespaceMemberParams struct {
	NamespaceID string
	UserID      string
	Role        string
}

// ListMembers returns the namespace's members, owner first.
func (s *namespaceService) ListMembers(ctx context.Context, namespaceID string) ([]NamespaceMember, error) {
	nsID, err := parseUUID(namespaceID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListNamespaceMembers(ctx, nsID)
	if err != nil {
		return nil, fmt.Errorf("listing namespace members: %w", err)
	}
	out := make([]NamespaceMember, len(rows))
	for i, m := range rows {
		out[i] = namespaceMemberFromRepo(m)
	}
	return out, nil
}

// SetMember adds a member or changes an existing member's role.
//
// Two of the three guard rails live here, because both are about the namespace
// rather than about the caller:
//
//   - The owner cannot be demoted. namespace_one_owner permits zero owners as
//     readily as one, so the index cannot catch this and an explicit read has
//     to: demoting the owner would leave a namespace nobody can administer.
//   - A second owner cannot be created. That one the index does catch, and
//     catching it rather than pre-reading is deliberate — a SELECT-then-INSERT
//     would race a concurrent grant and admit two owners under load.
//
// The third — a member may not grant a role they do not themselves hold — is
// the caller's own role and is enforced at the API boundary, where the caller's
// grants are already resolved.
func (s *namespaceService) SetMember(ctx context.Context, params SetNamespaceMemberParams) (NamespaceMember, error) {
	nsID, err := parseUUID(params.NamespaceID)
	if err != nil {
		return NamespaceMember{}, ErrNotFound
	}
	userID, err := parseUUID(params.UserID)
	if err != nil {
		return NamespaceMember{}, ErrNotFound
	}
	if !authz.Role(params.Role).Valid() {
		return NamespaceMember{}, &ValidationError{
			Message: fmt.Sprintf("unknown role %q", params.Role),
		}
	}

	existing, err := s.repo.GetNamespaceMember(ctx, repository.GetNamespaceMemberParams{
		NamespaceID: nsID,
		UserID:      userID,
	})
	switch {
	case err == nil:
		if existing.Role == string(authz.RoleOwner) && params.Role != string(authz.RoleOwner) {
			return NamespaceMember{}, ErrConflict
		}
	case errors.Is(err, pgx.ErrNoRows):
		// New member; nothing to demote.
	default:
		return NamespaceMember{}, fmt.Errorf("reading namespace member: %w", err)
	}

	row, err := s.repo.AddNamespaceMember(ctx, repository.AddNamespaceMemberParams{
		NamespaceID: nsID,
		UserID:      userID,
		Role:        params.Role,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return NamespaceMember{}, ErrConflict
		}
		return NamespaceMember{}, fmt.Errorf("setting namespace member: %w", err)
	}
	return namespaceMemberFromRepo(row), nil
}

// RemoveMember removes a member. Removing the owner is refused for the same
// reason demoting them is: the namespace would be left with nobody who can
// administer it, and unlike a demote there is no constraint that would notice.
func (s *namespaceService) RemoveMember(ctx context.Context, namespaceID, userID string) error {
	nsID, err := parseUUID(namespaceID)
	if err != nil {
		return ErrNotFound
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return ErrNotFound
	}

	existing, err := s.repo.GetNamespaceMember(ctx, repository.GetNamespaceMemberParams{
		NamespaceID: nsID,
		UserID:      uid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("reading namespace member: %w", err)
	}
	if existing.Role == string(authz.RoleOwner) {
		return ErrConflict
	}

	rows, err := s.repo.RemoveNamespaceMember(ctx, repository.RemoveNamespaceMemberParams{
		NamespaceID: nsID,
		UserID:      uid,
	})
	if err != nil {
		return fmt.Errorf("removing namespace member: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func namespaceMemberFromRepo(m repository.NamespaceMember) NamespaceMember {
	out := NamespaceMember{
		NamespaceID: uuidToStr(m.NamespaceID),
		UserID:      uuidToStr(m.UserID),
		Role:        m.Role,
	}
	if m.CreatedAt.Valid {
		out.CreatedAt = m.CreatedAt.Time
	}
	return out
}
