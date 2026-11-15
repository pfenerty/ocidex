package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// Cluster agent credentials (ocidex-70eo.5, ADR-0044 K8). Every operation here
// is manage_cluster on the cluster's namespace: a credential is part of the
// cluster's configuration, and minting one hands out push access to it.

// ListClusterCredentials lists the cluster's agent credentials, whoever minted them.
func (h *Handler) ListClusterCredentials(ctx context.Context, in *ListClusterCredentialsInput) (*ListClusterCredentialsOutput, error) {
	if err := h.clusterCapabilityCheck(ctx, in.ID, authz.CapManageCluster); err != nil {
		return nil, err
	}
	creds, err := h.clusterService.ListCredentials(ctx, in.ID)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListClusterCredentialsOutput{}
	out.Body.Data = make([]ClusterCredentialResponse, len(creds))
	for i, c := range creds {
		out.Body.Data[i] = toClusterCredentialResponse(c)
	}
	return out, nil
}

// CreateClusterCredential mints a credential that may only push this
// cluster's inventory. The key is in the response and nowhere else.
func (h *Handler) CreateClusterCredential(ctx context.Context, in *CreateClusterCredentialInput) (*ClusterCredentialOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	cluster, err := h.clusterService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if err := h.requireNamespaceCapability(ctx, user, cluster.NamespaceID, authz.CapManageCluster); err != nil {
		return nil, err
	}
	// The credential acts with its owner's roles, so an owner who could not
	// push would mint a key that is refused on its first use.
	if err := h.requireNamespaceCapability(ctx, user, cluster.NamespaceID, authz.CapPushInventory); err != nil {
		return nil, err
	}
	name := in.Body.Name
	if name == "" {
		name = cluster.Name + "-agent"
	}
	cred, err := h.clusterService.CreateCredential(ctx, in.ID, user.ID, name)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &ClusterCredentialOutput{Body: toClusterCredentialResponse(cred)}, nil
}

// RotateClusterCredential replaces a credential with a new key of the same
// name, owned by the caller, and revokes the old one.
func (h *Handler) RotateClusterCredential(ctx context.Context, in *ClusterCredentialInput) (*ClusterCredentialOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	cluster, err := h.clusterService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if err := h.requireNamespaceCapability(ctx, user, cluster.NamespaceID, authz.CapManageCluster); err != nil {
		return nil, err
	}
	if err := h.requireNamespaceCapability(ctx, user, cluster.NamespaceID, authz.CapPushInventory); err != nil {
		return nil, err
	}
	cred, err := h.clusterService.RotateCredential(ctx, in.ID, in.CredentialID, user.ID)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &ClusterCredentialOutput{Body: toClusterCredentialResponse(cred)}, nil
}

// RevokeClusterCredential deletes one of the cluster's credentials.
func (h *Handler) RevokeClusterCredential(ctx context.Context, in *ClusterCredentialInput) (*struct{}, error) {
	if err := h.clusterCapabilityCheck(ctx, in.ID, authz.CapManageCluster); err != nil {
		return nil, err
	}
	if err := h.clusterService.RevokeCredential(ctx, in.ID, in.CredentialID); err != nil {
		return nil, mapServiceError(err)
	}
	return nil, nil
}

func toClusterCredentialResponse(c service.ClusterCredential) ClusterCredentialResponse {
	out := ClusterCredentialResponse{
		ID:        c.ID,
		Name:      c.Name,
		Prefix:    c.Prefix,
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
		OwnerID:   c.OwnerID,
		OwnerName: c.OwnerName,
		Key:       c.Plaintext,
	}
	if c.LastUsedAt != nil {
		out.LastUsedAt = c.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return out
}
