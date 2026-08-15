package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
)

// canManageNamespace returns true if the user is an admin or the namespace owner.
// This is the only ownership check in the system that matters: sources and
// registries inherit their answer from the namespace above them (ADR-039).
func canManageNamespace(user service.AuthUser, ns service.Namespace) bool {
	if user.Role == roleAdmin {
		return true
	}
	if ns.OwnerID != nil && user.ID.Valid {
		return *ns.OwnerID == uuidToStr(user.ID)
	}
	return false
}

// ListNamespaces returns the namespaces visible to the current user: their own,
// plus every public one.
func (h *Handler) ListNamespaces(ctx context.Context, _ *ListNamespacesInput) (*ListNamespacesOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	rows, err := h.namespaceService.List(ctx, service.VisibilityFilter{
		IsAdmin: user.Role == roleAdmin,
		UserID:  user.ID,
	})
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
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	ns, err := h.namespaceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("namespace not found")
	}
	if !canManageNamespace(user, ns) && ns.Visibility == visibilityPrivate {
		return nil, huma.Error404NotFound("namespace not found")
	}
	return &GetNamespaceOutput{Body: toNamespaceResponse(ns, nil)}, nil
}

// GetNamespaceByName returns a single namespace by name.
func (h *Handler) GetNamespaceByName(ctx context.Context, in *GetNamespaceByNameInput) (*GetNamespaceByNameOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	ns, err := h.namespaceService.GetByName(ctx, in.Name)
	if err != nil {
		return nil, huma.Error404NotFound("namespace not found")
	}
	if !canManageNamespace(user, ns) && ns.Visibility == visibilityPrivate {
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
	if !canManageNamespace(user, existing) {
		return nil, huma.Error403Forbidden("not the namespace owner")
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
	if !canManageNamespace(user, existing) {
		return nil, huma.Error403Forbidden("not the namespace owner")
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

// namespaceOwnerCheck resolves the namespace owning a source and reports whether
// the user may manage it. Every source-level authorization decision routes
// through here rather than growing its own rule (ADR-039).
func (h *Handler) namespaceOwnerCheck(ctx context.Context, user service.AuthUser, namespaceID string) error {
	ns, err := h.namespaceService.Get(ctx, namespaceID)
	if err != nil {
		return huma.Error404NotFound("namespace not found")
	}
	if !canManageNamespace(user, ns) {
		return huma.Error403Forbidden("not the namespace owner")
	}
	return nil
}
