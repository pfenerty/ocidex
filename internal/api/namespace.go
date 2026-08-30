package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// canReadPrivate reports whether the caller may see a private namespace's
// content. It is the read half of what canManageNamespace used to answer
// (ocidex-y0hg.5): membership of a private namespace is precisely the right to
// read it, so every role holds CapReadPrivate and a non-member holds nothing.
//
// A public namespace never reaches here — its rows are visible through the SQL
// visibility functions — which is why the callers all read
// `ns.Visibility == visibilityPrivate && !canReadPrivate(...)`.
func canReadPrivate(ctx context.Context, ns service.Namespace) bool {
	return canFromContext(ctx, ns.ID, authz.CapReadPrivate)
}

// ListNamespaces returns the namespaces visible to the current user: their own,
// plus every public one.
func (h *Handler) ListNamespaces(ctx context.Context, _ *ListNamespacesInput) (*ListNamespacesOutput, error) {
	return h.listNamespaces(ctx, visibilityFilterFromContext(ctx))
}

// ListMyNamespaces returns only the namespaces the caller owns. It shares
// ListNamespaces' body and differs solely in the filter, so the two cannot
// drift apart in what they project (ocidex-998g.2).
func (h *Handler) ListMyNamespaces(ctx context.Context, _ *ListMyNamespacesInput) (*ListNamespacesOutput, error) {
	return h.listNamespaces(ctx, ownedFilterFromContext(ctx))
}

func (h *Handler) listNamespaces(ctx context.Context, vis service.VisibilityFilter) (*ListNamespacesOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	rows, err := h.namespaceService.List(ctx, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	ownerNames := map[string]string{}
	if users, err := h.authService.ListUsers(ctx); err == nil {
		for _, u := range users {
			ownerNames[uuidToStr(u.ID)] = u.GitHubUsername
		}
	}

	out := &ListNamespacesOutput{}
	out.Body.Data = make([]NamespaceResponse, len(rows))
	for i, ns := range rows {
		var ownerUsername *string
		if ns.OwnerID != nil {
			if name, ok := ownerNames[*ns.OwnerID]; ok {
				ownerUsername = &name
			}
		}
		out.Body.Data[i] = toNamespaceResponse(ns, ownerUsername)
	}
	return out, nil
}

// GetNamespace returns a single namespace. A private namespace the caller does
// not own is reported as missing rather than forbidden, so its existence is not
// leaked.
func (h *Handler) GetNamespace(ctx context.Context, in *GetNamespaceInput) (*GetNamespaceOutput, error) {
	_, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	ns, err := h.namespaceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("namespace not found")
	}
	if ns.Visibility == visibilityPrivate && !canReadPrivate(ctx, ns) {
		return nil, huma.Error404NotFound("namespace not found")
	}
	return &GetNamespaceOutput{Body: toNamespaceResponse(ns, nil)}, nil
}

// GetNamespaceByName returns a single namespace by name.
func (h *Handler) GetNamespaceByName(ctx context.Context, in *GetNamespaceByNameInput) (*GetNamespaceByNameOutput, error) {
	_, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	ns, err := h.namespaceService.GetByName(ctx, in.Name)
	if err != nil {
		return nil, huma.Error404NotFound("namespace not found")
	}
	if ns.Visibility == visibilityPrivate && !canReadPrivate(ctx, ns) {
		return nil, huma.Error404NotFound("namespace not found")
	}
	return &GetNamespaceByNameOutput{Body: toNamespaceResponse(ns, nil)}, nil
}

// CreateNamespace creates a namespace owned by the calling user. Any
// authenticated user with a write-capable key may create one.
func (h *Handler) CreateNamespace(ctx context.Context, in *CreateNamespaceInput) (*CreateNamespaceOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	ns, err := h.namespaceService.Create(ctx, service.CreateNamespaceParams{
		Name:       in.Body.Name,
		OwnerID:    user.ID,
		Visibility: in.Body.Visibility,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &CreateNamespaceOutput{Body: toNamespaceResponse(ns, nil)}, nil
}

// UpdateNamespace renames or re-scopes a namespace. Ownership is not
// transferable through this endpoint.
func (h *Handler) UpdateNamespace(ctx context.Context, in *UpdateNamespaceInput) (*UpdateNamespaceOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.namespaceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("namespace not found")
	}
	if !can(user, existing.ID, authz.CapManageMember) {
		return nil, huma.Error403Forbidden("forbidden")
	}
	ns, err := h.namespaceService.Update(ctx, service.UpdateNamespaceParams{
		ID:         in.ID,
		Name:       in.Body.Name,
		Visibility: in.Body.Visibility,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &UpdateNamespaceOutput{Body: toNamespaceResponse(ns, nil)}, nil
}

// DeleteNamespace removes a namespace and everything ingested under it. This is
// a tenant-level delete, not a config tidy-up, so it is owner- or admin-only.
func (h *Handler) DeleteNamespace(ctx context.Context, in *DeleteNamespaceInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.namespaceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("namespace not found")
	}
	if !can(user, existing.ID, authz.CapDeleteNamespace) {
		return nil, huma.Error403Forbidden("forbidden")
	}
	if err := h.namespaceService.Delete(ctx, in.ID); err != nil {
		return nil, mapServiceError(err)
	}
	return nil, nil
}

func toNamespaceResponse(ns service.Namespace, ownerUsername *string) NamespaceResponse {
	return NamespaceResponse{
		ID:            ns.ID,
		Name:          ns.Name,
		Visibility:    ns.Visibility,
		OwnerID:       ns.OwnerID,
		OwnerUsername: ownerUsername,
		CreatedAt:     ns.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     ns.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// requireNamespaceCapability is RequireCapability for the operations that
// cannot use it: those whose target namespace is named in the request body, or
// reached through a resource the handler has already loaded, and so is not
// knowable from the path a middleware sees. Every such authorization decision
// routes through here rather than growing its own rule (ADR-039).
//
// It resolves the namespace first and 404s if it is missing, which is what
// makes "you may not act on this" and "this is not here" the same answer for a
// caller who cannot see it either way.
func (h *Handler) requireNamespaceCapability(
	ctx context.Context, user service.AuthUser, namespaceID string, c authz.Capability,
) error {
	if _, err := h.namespaceService.Get(ctx, namespaceID); err != nil {
		return huma.Error404NotFound("namespace not found")
	}
	if !can(user, namespaceID, c) {
		return huma.Error403Forbidden("forbidden")
	}
	return nil
}
