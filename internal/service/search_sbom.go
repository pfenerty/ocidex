package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

func (s *searchService) GetSBOM(ctx context.Context, id pgtype.UUID, includeRaw bool, vis VisibilityFilter) (SBOMDetail, error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      id,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SBOMDetail{}, ErrNotFound
		}
		return SBOMDetail{}, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return SBOMDetail{}, ErrNotFound
	}

	row, err := q.GetSBOM(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SBOMDetail{}, ErrNotFound
		}
		return SBOMDetail{}, fmt.Errorf("getting sbom: %w", err)
	}

	count, err := q.CountSBOMComponents(ctx, id)
	if err != nil {
		return SBOMDetail{}, fmt.Errorf("counting components: %w", err)
	}

	detail := SBOMDetail{
		SBOMSummary: SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
			ComponentCount: count,
		},
	}

	if includeRaw {
		raw, err := q.GetSBOMRaw(ctx, id)
		if err != nil {
			return SBOMDetail{}, fmt.Errorf("getting raw bom: %w", err)
		}
		detail.RawBOM = raw
	}

	// Fetch enrichment data for this SBOM.
	enrichRows, err := q.ListEnrichmentsBySBOM(ctx, id)
	if err != nil {
		return SBOMDetail{}, fmt.Errorf("listing enrichments: %w", err)
	}
	for _, e := range enrichRows {
		if e.Status != "success" || len(e.Data) == 0 {
			continue
		}
		if detail.Enrichments == nil {
			detail.Enrichments = make(map[string]json.RawMessage)
		}
		detail.Enrichments[e.EnricherName] = json.RawMessage(e.Data)
	}

	return detail, nil
}

func (s *searchService) ListSBOMs(ctx context.Context, filter SBOMFilter) (PagedResult[SBOMSummary], error) {
	q := repository.New(s.db)

	rows, err := q.ListSBOMs(ctx, repository.ListSBOMsParams{
		SerialNumber: textOrNull(filter.SerialNumber),
		Digest:       textOrNull(filter.Digest),
		UserID:       filter.Visibility.UserID,
		IsAdmin:      visAdminBool(filter.Visibility),
		RowLimit:     filter.Limit,
		RowOffset:    filter.Offset,
	})
	if err != nil {
		return PagedResult[SBOMSummary]{}, fmt.Errorf("listing sboms: %w", err)
	}

	var total int64
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
		})
	}

	return PagedResult[SBOMSummary]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) ListSBOMsByArtifact(ctx context.Context, artifactID pgtype.UUID, subjectVersion, imageVersion string, limit, offset int32, vis VisibilityFilter) (PagedResult[SBOMSummary], error) {
	q := repository.New(s.db)

	rows, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:     artifactID,
		SubjectVersion: textOrNull(subjectVersion),
		ImageVersion:   textOrNull(imageVersion),
		UserID:         vis.UserID,
		IsAdmin:        visAdminBool(vis),
		RowLimit:       limit,
		RowOffset:      offset,
	})
	if err != nil {
		return PagedResult[SBOMSummary]{}, fmt.Errorf("listing sboms by artifact: %w", err)
	}

	artifactIDStr := uuidToString(artifactID)
	var total int64
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		summary := SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     &artifactIDStr,
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
			ComponentCount: row.ComponentCount,
		}
		if row.BuildDate.Valid {
			t := row.BuildDate.Time
			summary.BuildDate = &t
		}
		if s, ok := row.ImageVersion.(string); ok && s != "" {
			summary.ImageVersion = &s
		}
		if s, ok := row.Architecture.(string); ok && s != "" {
			summary.Architecture = &s
		}
		if s, ok := row.Revision.(string); ok && s != "" {
			summary.Revision = &s
		}
		if s, ok := row.SourceUrl.(string); ok && s != "" {
			summary.SourceURL = &s
		}
		summary.Sufficient = row.EnrichmentSufficient
		items = append(items, summary)
	}

	return PagedResult[SBOMSummary]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// ListSBOMsByDigest returns SBOMs matching the given container image digest.
func (s *searchService) ListSBOMsByDigest(ctx context.Context, digest string, limit, offset int32, vis VisibilityFilter) (PagedResult[SBOMSummary], error) {
	q := repository.New(s.db)

	rows, err := q.ListSBOMsByDigest(ctx, repository.ListSBOMsByDigestParams{
		Digest:    textOrNull(digest),
		UserID:    vis.UserID,
		IsAdmin:   visAdminBool(vis),
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[SBOMSummary]{}, fmt.Errorf("listing sboms by digest: %w", err)
	}

	var total int64
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, SBOMSummary{
			ID:             uuidToString(row.ID),
			SerialNumber:   textToPtr(row.SerialNumber),
			SpecVersion:    row.SpecVersion,
			Version:        row.Version,
			ArtifactID:     uuidToPtr(row.ArtifactID),
			SubjectVersion: textToPtr(row.SubjectVersion),
			Digest:         textToPtr(row.Digest),
			CreatedAt:      row.CreatedAt.Time,
		})
	}

	return PagedResult[SBOMSummary]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// GetSBOMDependencies returns the dependency graph for an SBOM.
func (s *searchService) GetSBOMDependencies(ctx context.Context, sbomID pgtype.UUID, vis VisibilityFilter) (DependencyGraph, error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      sbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DependencyGraph{}, ErrNotFound
		}
		return DependencyGraph{}, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return DependencyGraph{}, ErrNotFound
	}

	comps, err := q.ListSBOMComponents(ctx, sbomID)
	if err != nil {
		return DependencyGraph{}, fmt.Errorf("listing components: %w", err)
	}

	deps, err := q.ListDependenciesBySBOM(ctx, sbomID)
	if err != nil {
		return DependencyGraph{}, fmt.Errorf("listing dependencies: %w", err)
	}

	nodes := make([]ComponentSummary, 0, len(comps))
	for _, c := range comps {
		nodes = append(nodes, toComponentSummary(c.ID, sbomID, c.BomRef, c.Type, c.Name, c.GroupName, c.Version, c.Purl))
	}

	edges := make([]DependencyEdge, 0, len(deps))
	for _, d := range deps {
		edges = append(edges, DependencyEdge{From: d.Ref, To: d.DependsOn})
	}

	return DependencyGraph{Nodes: nodes, Edges: edges}, nil
}

// ListSBOMComponents returns all components belonging to an SBOM.
func (s *searchService) ListSBOMComponents(ctx context.Context, sbomID pgtype.UUID, vis VisibilityFilter) ([]ComponentSummary, error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      sbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return nil, ErrNotFound
	}

	rows, err := q.ListSBOMComponents(ctx, sbomID)
	if err != nil {
		return nil, fmt.Errorf("listing sbom components: %w", err)
	}

	items := make([]ComponentSummary, 0, len(rows))
	for _, c := range rows {
		items = append(items, toComponentSummary(c.ID, sbomID, c.BomRef, c.Type, c.Name, c.GroupName, c.Version, c.Purl))
	}

	return items, nil
}
