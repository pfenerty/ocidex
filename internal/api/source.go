package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// ListSources returns the sources visible to the current user, optionally
// scoped to one namespace. Visibility is always resolved through the owning
// namespace — a source carries none of its own (ADR-039).
func (h *Handler) ListSources(ctx context.Context, in *ListSourcesInput) (*ListSourcesOutput, error) {
	_, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}

	out := &ListSourcesOutput{}

	if in.NamespaceID != "" {
		ns, err := h.namespaceService.Get(ctx, in.NamespaceID)
		if err != nil {
			return nil, huma.Error404NotFound("namespace not found")
		}
		if ns.Visibility == visibilityPrivate && !canReadPrivate(ctx, ns) {
			return nil, huma.Error404NotFound("namespace not found")
		}
		rows, err := h.sourceService.ListByNamespace(ctx, in.NamespaceID)
		if err != nil {
			return nil, mapServiceError(err)
		}
		out.Body.Data = make([]SourceResponse, len(rows))
		for i, src := range rows {
			src.NamespaceName = ns.Name
			out.Body.Data[i] = toSourceResponse(src)
		}
		return out, nil
	}

	return h.listSources(ctx, visibilityFilterFromContext(ctx))
}

// ListMySources returns only the sources in namespaces the caller owns. It has
// no namespace query parameter: /sources?namespace_id= already covers "one
// namespace", and the point of this collection is that the caller does not have
// to know their namespace IDs first (ocidex-998g.2).
func (h *Handler) ListMySources(ctx context.Context, _ *ListMySourcesInput) (*ListSourcesOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	return h.listSources(ctx, ownedFilterFromContext(ctx))
}

func (h *Handler) listSources(ctx context.Context, vis service.VisibilityFilter) (*ListSourcesOutput, error) {
	rows, err := h.sourceService.List(ctx, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListSourcesOutput{}
	out.Body.Data = make([]SourceResponse, len(rows))
	for i, src := range rows {
		out.Body.Data[i] = toSourceResponse(src)
	}
	return out, nil
}

// GetSource returns a single source, gated on its namespace's visibility.
func (h *Handler) GetSource(ctx context.Context, in *GetSourceInput) (*GetSourceOutput, error) {
	_, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	src, err := h.sourceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("source not found")
	}
	ns, err := h.namespaceService.Get(ctx, src.NamespaceID)
	if err != nil {
		return nil, huma.Error404NotFound("source not found")
	}
	if ns.Visibility == visibilityPrivate && !canReadPrivate(ctx, ns) {
		return nil, huma.Error404NotFound("source not found")
	}
	src.NamespaceName = ns.Name
	return &GetSourceOutput{Body: toSourceResponse(src)}, nil
}

// CreateSource creates an upload source in a namespace the caller owns. OCI
// registry sources are created through POST /api/v1/registries instead, because
// the registry row has to be written in the same statement.
func (h *Handler) CreateSource(ctx context.Context, in *CreateSourceInput) (*CreateSourceOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if err := h.requireNamespaceCapability(ctx, user, in.Body.NamespaceID, authz.CapManageSource); err != nil {
		return nil, err
	}
	src, err := h.sourceService.Create(ctx, service.CreateSourceParams{
		NamespaceID: in.Body.NamespaceID,
		Kind:        service.SourceKindUpload,
		Name:        in.Body.Name,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &CreateSourceOutput{Body: toSourceResponse(src)}, nil
}

// UpdateSource renames a source.
func (h *Handler) UpdateSource(ctx context.Context, in *UpdateSourceInput) (*UpdateSourceOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.sourceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("source not found")
	}
	if err := h.requireNamespaceCapability(ctx, user, existing.NamespaceID, authz.CapManageSource); err != nil {
		return nil, err
	}
	src, err := h.sourceService.Update(ctx, service.UpdateSourceParams{
		ID:   in.ID,
		Name: in.Body.Name,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &UpdateSourceOutput{Body: toSourceResponse(src)}, nil
}

// DeleteSource removes a source and, for OCI sources, the registry row beneath
// it. The namespace and its SBOMs survive.
func (h *Handler) DeleteSource(ctx context.Context, in *DeleteSourceInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.sourceService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("source not found")
	}
	if err := h.requireNamespaceCapability(ctx, user, existing.NamespaceID, authz.CapManageSource); err != nil {
		return nil, err
	}
	if err := h.sourceService.Delete(ctx, in.ID); err != nil {
		return nil, mapServiceError(err)
	}
	return nil, nil
}

func toSourceResponse(src service.Source) SourceResponse {
	return SourceResponse{
		ID:            src.ID,
		NamespaceID:   src.NamespaceID,
		NamespaceName: src.NamespaceName,
		Kind:          src.Kind,
		Name:          src.Name,
		CreatedAt:     src.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     src.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}
