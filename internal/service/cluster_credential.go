package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// ClusterCredential is an agent credential bound to one cluster
// (ocidex-70eo.5, ADR-0044 K8). It is an API key whose only power is pushing
// that cluster's inventory. Plaintext is set only on the response that minted
// it; the server keeps a hash.
type ClusterCredential struct {
	ID         string
	Name       string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	// OwnerID and OwnerName are the user who minted it. The key narrows with
	// that user's live roles, so the owner is what explains a credential that
	// stopped working after a membership change.
	OwnerID   string
	OwnerName string
	Plaintext string
}

// CreateCredential mints a credential bound to clusterID and owned by userID.
func (s *clusterService) CreateCredential(ctx context.Context, clusterID string, userID pgtype.UUID, name string) (ClusterCredential, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return ClusterCredential{}, ErrNotFound
	}
	plaintext, hash, prefix, err := newAPIKeyMaterial()
	if err != nil {
		return ClusterCredential{}, err
	}
	row, err := s.repo.CreateClusterCredential(ctx, repository.CreateClusterCredentialParams{
		UserID:    userID,
		Name:      name,
		KeyHash:   hash,
		Prefix:    prefix,
		ClusterID: cid,
	})
	if err != nil {
		return ClusterCredential{}, fmt.Errorf("creating cluster credential: %w", err)
	}
	return ClusterCredential{
		ID:        uuidToStr(row.ID),
		Name:      row.Name,
		Prefix:    row.Prefix,
		CreatedAt: row.CreatedAt.Time,
		OwnerID:   uuidToStr(userID),
		Plaintext: plaintext,
	}, nil
}

// ListCredentials lists every credential bound to the cluster, whoever minted
// it: the namespace's cluster managers manage them together.
func (s *clusterService) ListCredentials(ctx context.Context, clusterID string) ([]ClusterCredential, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListClusterCredentials(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("listing cluster credentials: %w", err)
	}
	out := make([]ClusterCredential, len(rows))
	for i, r := range rows {
		c := ClusterCredential{
			ID:        uuidToStr(r.ID),
			Name:      r.Name,
			Prefix:    r.Prefix,
			CreatedAt: r.CreatedAt.Time,
			OwnerID:   uuidToStr(r.UserID),
			OwnerName: displayName(r.DisplayName),
		}
		if r.LastUsedAt.Valid {
			t := r.LastUsedAt.Time
			c.LastUsedAt = &t
		}
		out[i] = c
	}
	return out, nil
}

// RevokeCredential deletes one of the cluster's credentials. ErrNotFound when
// the id is not a credential of this cluster.
func (s *clusterService) RevokeCredential(ctx context.Context, clusterID, credentialID string) error {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return ErrNotFound
	}
	kid, err := parseUUID(credentialID)
	if err != nil {
		return ErrNotFound
	}
	n, err := s.repo.DeleteClusterCredential(ctx, repository.DeleteClusterCredentialParams{ID: kid, ClusterID: cid})
	if err != nil {
		return fmt.Errorf("revoking cluster credential: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateCredential replaces a credential with a new one of the same name,
// owned by userID, and revokes the old one in the same statement. The agent
// stops authenticating until it is given the new key: rotation for overlap is
// CreateCredential, roll the agent, then RevokeCredential.
func (s *clusterService) RotateCredential(ctx context.Context, clusterID, credentialID string, userID pgtype.UUID) (ClusterCredential, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return ClusterCredential{}, ErrNotFound
	}
	kid, err := parseUUID(credentialID)
	if err != nil {
		return ClusterCredential{}, ErrNotFound
	}
	plaintext, hash, prefix, err := newAPIKeyMaterial()
	if err != nil {
		return ClusterCredential{}, err
	}
	row, err := s.repo.RotateClusterCredential(ctx, repository.RotateClusterCredentialParams{
		UserID:    userID,
		KeyHash:   hash,
		Prefix:    prefix,
		ClusterID: cid,
		OldID:     kid,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCredential{}, ErrNotFound
	}
	if err != nil {
		return ClusterCredential{}, fmt.Errorf("rotating cluster credential: %w", err)
	}
	return ClusterCredential{
		ID:        uuidToStr(row.ID),
		Name:      row.Name,
		Prefix:    row.Prefix,
		CreatedAt: row.CreatedAt.Time,
		OwnerID:   uuidToStr(userID),
		Plaintext: plaintext,
	}, nil
}
