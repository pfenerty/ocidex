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

func (s *searchService) ListSBOMs(ctx context.Context, filter SBOMFilter) (CursorPage[SBOMSummary], error) {
	q := repository.New(s.db)

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListSBOMs(ctx, repository.ListSBOMsParams{
		SerialNumber:    textOrNull(filter.SerialNumber),
		Digest:          textOrNull(filter.Digest),
		UserID:          filter.Visibility.UserID,
		IsAdmin:         visAdminBool(filter.Visibility),
		HasCursor:       pgtype.Bool{Bool: filter.HasCursor, Valid: true},
		CursorCreatedAt: pgtype.Timestamptz{Time: filter.CursorCreatedAt, Valid: filter.HasCursor},
		CursorID:        uuidOrNull(filter.CursorID),
		RowLimit:        filter.Limit + 1,
	})
	if err != nil {
		return CursorPage[SBOMSummary]{}, fmt.Errorf("listing sboms: %w", err)
	}

	hasMore := len(rows) > int(filter.Limit)
	if hasMore {
		rows = rows[:filter.Limit]
	}

	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
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

	return CursorPage[SBOMSummary]{Data: items, HasMore: hasMore}, nil
}

func (s *searchService) ListSBOMsByArtifact(ctx context.Context, artifactID pgtype.UUID, subjectVersion, imageVersion string, page SBOMByArtifactPage, vis VisibilityFilter) (CursorPage[SBOMSummary], error) {
	q := repository.New(s.db)

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListSBOMsByArtifact(ctx, repository.ListSBOMsByArtifactParams{
		ArtifactID:      artifactID,
		SubjectVersion:  textOrNull(subjectVersion),
		ImageVersion:    textOrNull(imageVersion),
		UserID:          vis.UserID,
		IsAdmin:         visAdminBool(vis),
		HasCursor:       pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorCreatedAt: pgtype.Timestamptz{Time: page.CursorCreatedAt, Valid: page.HasCursor},
		CursorID:        uuidOrNull(page.CursorID),
		RowLimit:        page.Limit + 1,
	})
	if err != nil {
		return CursorPage[SBOMSummary]{}, fmt.Errorf("listing sboms by artifact: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	artifactIDStr := uuidToString(artifactID)
	items := make([]SBOMSummary, 0, len(rows))
	for _, row := range rows {
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
		if row.Flavor.Valid && row.Flavor.String != "" {
			summary.Flavor = &row.Flavor.String
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

	return CursorPage[SBOMSummary]{Data: items, HasMore: hasMore}, nil
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
//
//nolint:gocyclo
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

	rawMeta, err := q.GetSBOMMetadataBomRef(ctx, sbomID)
	if err != nil {
		return DependencyGraph{}, fmt.Errorf("getting metadata bom-ref: %w", err)
	}
	var metaBomRef string
	if rawMeta != nil {
		if s, ok := rawMeta.(string); ok {
			metaBomRef = s
		}
	}

	nodes := make([]ComponentSummary, 0, len(comps))
	for _, c := range comps {
		nodes = append(nodes, toComponentSummary(c.ID, sbomID, c.BomRef, c.Type, c.Name, c.GroupName, c.Version, c.Purl))
	}

	edges := make([]DependencyEdge, 0, len(deps))
	outEdges := make(map[string][]string, len(deps))
	inEdge := make(map[string]int, len(deps))
	for _, d := range deps {
		edges = append(edges, DependencyEdge{From: d.Ref, To: d.DependsOn})
		outEdges[d.Ref] = append(outEdges[d.Ref], d.DependsOn)
		inEdge[d.DependsOn]++
	}

	// Anchor on metadata.component.bom-ref; fall back to nodes with no incoming edges.
	roots := outEdges[metaBomRef]
	if len(roots) == 0 {
		for _, n := range nodes {
			ref := ""
			if n.BomRef != nil {
				ref = *n.BomRef
			}
			if ref != "" && inEdge[ref] == 0 && len(outEdges[ref]) > 0 {
				roots = append(roots, ref)
			}
		}
	}

	return DependencyGraph{Nodes: nodes, Edges: edges, Roots: roots}, nil
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

// ListSBOMComponentsPage returns a keyset page of an SBOM's components, ordered
// by (name, group_name, id). Access is gated the same way as ListSBOMComponents.
func (s *searchService) ListSBOMComponentsPage(ctx context.Context, sbomID pgtype.UUID, page ComponentPage, vis VisibilityFilter) (CursorPage[ComponentSummary], error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      sbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CursorPage[ComponentSummary]{}, ErrNotFound
		}
		return CursorPage[ComponentSummary]{}, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return CursorPage[ComponentSummary]{}, ErrNotFound
	}

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListSBOMComponentsPage(ctx, repository.ListSBOMComponentsPageParams{
		SbomID:      sbomID,
		HasCursor:   pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorName:  textOrNull(page.CursorName),
		CursorGroup: pgtype.Text{String: page.CursorGroup, Valid: page.HasCursor},
		CursorID:    uuidOrNull(page.CursorID),
		RowLimit:    page.Limit + 1,
	})
	if err != nil {
		return CursorPage[ComponentSummary]{}, fmt.Errorf("listing sbom components: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	items := make([]ComponentSummary, 0, len(rows))
	for _, c := range rows {
		items = append(items, toComponentSummary(c.ID, sbomID, c.BomRef, c.Type, c.Name, c.GroupName, c.Version, c.Purl))
	}

	return CursorPage[ComponentSummary]{Data: items, HasMore: hasMore}, nil
}
