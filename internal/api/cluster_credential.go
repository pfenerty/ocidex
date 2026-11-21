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
	creds, err := h.clusterAgents.ListCredentials(ctx, in.ID)
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
	cluster, err := h.clusters.Get(ctx, in.ID)
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
	cred, err := h.clusterAgents.CreateCredential(ctx, in.ID, user.ID, name)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ClusterCredentialOutput{Body: toClusterCredentialResponse(cred)}
	out.Body.ServerURL = h.cfg.APIBaseURL
	return out, nil
}

// RotateClusterCredential replaces a credential with a new key of the same
// name, owned by the caller, and revokes the old one.
func (h *Handler) RotateClusterCredential(ctx context.Context, in *ClusterCredentialInput) (*ClusterCredentialOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	cluster, err := h.clusters.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("cluster not found")
	}
	if err := h.requireNamespaceCapability(ctx, user, cluster.NamespaceID, authz.CapManageCluster); err != nil {
		return nil, err
	}
	if err := h.requireNamespaceCapability(ctx, user, cluster.NamespaceID, authz.CapPushInventory); err != nil {
		return nil, err
	}
	cred, err := h.clusterAgents.RotateCredential(ctx, in.ID, in.CredentialID, user.ID)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ClusterCredentialOutput{Body: toClusterCredentialResponse(cred)}
	out.Body.ServerURL = h.cfg.APIBaseURL
	return out, nil
}

// ConnectCluster registers a cluster and mints its first agent credential in
// one step (ocidex-70eo.6). Both capabilities are checked first: the cluster
// is manage_cluster, the key is useless without push_inventory.
func (h *Handler) ConnectCluster(ctx context.Context, in *ConnectClusterInput) (*ConnectClusterOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	for _, c := range []authz.Capability{authz.CapManageCluster, authz.CapPushInventory} {
		if err := h.requireNamespaceCapability(ctx, user, in.Body.NamespaceID, c); err != nil {
			return nil, err
		}
	}
	auto := true
	if in.Body.AutoIngest != nil {
		auto = *in.Body.AutoIngest
	}
	cluster, cred, err := h.clusters.Connect(ctx, service.ConnectClusterParams{
		NamespaceID: in.Body.NamespaceID,
		Name:        in.Body.Name,
		Description: in.Body.Description,
		AutoIngest:  auto,
		Owner:       user.ID,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ConnectClusterOutput{}
	out.Body.Cluster = toClusterResponse(cluster)
	out.Body.Credential = toClusterCredentialResponse(cred)
	out.Body.Credential.ServerURL = h.cfg.APIBaseURL
	return out, nil
}

// RevokeClusterCredential deletes one of the cluster's credentials.
func (h *Handler) RevokeClusterCredential(ctx context.Context, in *ClusterCredentialInput) (*struct{}, error) {
	if err := h.clusterCapabilityCheck(ctx, in.ID, authz.CapManageCluster); err != nil {
		return nil, err
	}
	if err := h.clusterAgents.RevokeCredential(ctx, in.ID, in.CredentialID); err != nil {
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
