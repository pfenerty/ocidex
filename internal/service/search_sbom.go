package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
	"github.com/pfenerty/ocidex/internal/repository"
)

const (
	sevCritical = "CRITICAL"
	sevHigh     = "HIGH"
	sevMedium   = "MEDIUM"
	sevLow      = "LOW"
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

	pkgCount, err := q.CountSBOMPackages(ctx, id)
	if err != nil {
		return SBOMDetail{}, fmt.Errorf("counting packages: %w", err)
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
		PackageCount: pkgCount,
	}

	if includeRaw {
		raw, err := q.GetSBOMRaw(ctx, id)
		if err != nil {
			return SBOMDetail{}, fmt.Errorf("getting raw bom: %w", err)
		}
		detail.RawBOM = raw
	}

	// Fetch enrichment data for this SBOM.
	detail.Enrichments, err = fetchEnrichments(ctx, q, id)
	if err != nil {
		return SBOMDetail{}, err
	}

	// Most recent provenance drift event, if this SBOM has ever been re-verified
	// with a different result than its original signing status.
	var signingProv provenance.Provenance
	if raw, hasProvenance := detail.Enrichments["provenance"]; hasProvenance {
		if err := json.Unmarshal(raw, &signingProv); err != nil {
			return SBOMDetail{}, fmt.Errorf("parsing provenance enrichment: %w", err)
		}
		drift, err := lookupProvenanceDrift(ctx, q, id)
		if err != nil {
			return SBOMDetail{}, err
		}
		detail.ProvenanceDrift = drift
	}
	detail.SigningStatus = provenance.SigningStatus(signingProv)

	// Vulnerability summary (joins component.purl against the vulnerability store).
	vsRows, err := q.GetSBOMVulnSummary(ctx, id)
	if err != nil {
		return SBOMDetail{}, fmt.Errorf("getting vuln summary: %w", err)
	}
	detail.VulnSummary = buildVulnSummary(vsRows)

	return detail, nil
}

// fetchEnrichments returns successful enrichment results for sbomID, keyed by
// enricher name. Nil when there are none.
func fetchEnrichments(ctx context.Context, q *repository.Queries, sbomID pgtype.UUID) (map[string]json.RawMessage, error) {
	rows, err := q.ListEnrichmentsBySBOM(ctx, sbomID)
	if err != nil {
		return nil, fmt.Errorf("listing enrichments: %w", err)
	}
	var enrichments map[string]json.RawMessage
	for _, e := range rows {
		if e.Status != "success" || len(e.Data) == 0 {
			continue
		}
		if enrichments == nil {
			enrichments = make(map[string]json.RawMessage)
		}
		enrichments[e.EnricherName] = json.RawMessage(e.Data)
	}
	return enrichments, nil
}

// lookupProvenanceDrift returns the most recent provenance_drift_events row
// for sbomID, or nil if the SBOM has never drifted.
func lookupProvenanceDrift(ctx context.Context, q *repository.Queries, sbomID pgtype.UUID) (*ProvenanceDriftSummary, error) {
	drift, err := q.GetLatestProvenanceDrift(ctx, sbomID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting provenance drift: %w", err)
	}
	return &ProvenanceDriftSummary{
		PreviousStatus: drift.PreviousStatus,
		NewStatus:      drift.NewStatus,
		Reason:         drift.Reason,
		DetectedAt:     drift.DetectedAt.Time,
	}, nil
}

// ListSBOMDriftHistory returns the full provenance drift event history for an
// SBOM, newest first. Visibility-gated the same way as GetSBOM.
func (s *searchService) ListSBOMDriftHistory(ctx context.Context, sbomID pgtype.UUID, limit, offset int32, vis VisibilityFilter) (PagedResult[ProvenanceDriftSummary], error) {
	q := repository.New(s.db)

	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      sbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PagedResult[ProvenanceDriftSummary]{}, ErrNotFound
		}
		return PagedResult[ProvenanceDriftSummary]{}, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return PagedResult[ProvenanceDriftSummary]{}, ErrNotFound
	}

	rows, err := q.ListProvenanceDriftBySBOM(ctx, repository.ListProvenanceDriftBySBOMParams{
		SbomID:    sbomID,
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[ProvenanceDriftSummary]{}, fmt.Errorf("listing sbom drift history: %w", err)
	}

	var total int64
	items := make([]ProvenanceDriftSummary, len(rows))
	for i, r := range rows {
		total = r.TotalCount
		items[i] = ProvenanceDriftSummary{
			PreviousStatus: r.PreviousStatus,
			NewStatus:      r.NewStatus,
			Reason:         r.Reason,
			DetectedAt:     r.DetectedAt.Time,
		}
	}
	return PagedResult[ProvenanceDriftSummary]{Data: items, Total: total, Limit: limit, Offset: offset}, nil
}

// ListRecentProvenanceDrift returns the most recent provenance drift events
// across every registry, newest first. Admin-only — callers must gate access
// since this bypasses per-registry visibility.
func (s *searchService) ListRecentProvenanceDrift(ctx context.Context, limit, offset int32) (PagedResult[RecentDriftEntry], error) {
	q := repository.New(s.db)

	rows, err := q.ListRecentProvenanceDrift(ctx, repository.ListRecentProvenanceDriftParams{
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[RecentDriftEntry]{}, fmt.Errorf("listing recent provenance drift: %w", err)
	}

	var total int64
	items := make([]RecentDriftEntry, len(rows))
	for i, r := range rows {
		total = r.TotalCount
		items[i] = RecentDriftEntry{
			ProvenanceDriftSummary: ProvenanceDriftSummary{
				PreviousStatus: r.PreviousStatus,
				NewStatus:      r.NewStatus,
				Reason:         r.Reason,
				DetectedAt:     r.DetectedAt.Time,
			},
			SBOMID:       uuidToString(r.SbomID),
			RegistryID:   uuidToPtr(r.RegistryID),
			RegistryName: textToPtr(r.RegistryName),
			ArtifactID:   uuidToPtr(r.ArtifactID),
			ArtifactName: textToPtr(r.ArtifactName),
			ArtifactType: textToPtr(r.ArtifactType),
		}
	}
	return PagedResult[RecentDriftEntry]{Data: items, Total: total, Limit: limit, Offset: offset}, nil
}

// buildVulnSummary folds per-severity counts into a VulnSummary, or nil when
// there are no findings.
func buildVulnSummary(rows []repository.GetSBOMVulnSummaryRow) *VulnSummary {
	if len(rows) == 0 {
		return nil
	}
	var vs VulnSummary
	for _, r := range rows {
		n := int(r.Count)
		vs.Total += n
		switch r.Severity.String {
		case sevCritical:
			vs.Critical += n
		case sevHigh:
			vs.High += n
		case sevMedium:
			vs.Medium += n
		case sevLow:
			vs.Low += n
		default:
			vs.Unknown += n
		}
	}
	if vs.Total == 0 {
		return nil
	}
	return &vs
}

// decorateComponentVulns sets VulnCount/MaxSeverity on each component from the
// SBOM's (purl → vulnerability) findings.
func decorateComponentVulns(ctx context.Context, q *repository.Queries, sbomID pgtype.UUID, items []ComponentSummary) error {
	rows, err := q.ListSBOMComponentVulns(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("listing component vulns: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	type agg struct {
		count                                int
		maxSeverity                          string
		critical, high, medium, low, unknown int
		seen                                 map[string]struct{}
	}
	byPurl := make(map[string]*agg, len(rows))
	for _, r := range rows {
		a := byPurl[r.Purl]
		if a == nil {
			a = &agg{seen: make(map[string]struct{})}
			byPurl[r.Purl] = a
		}
		canonicalID := r.CanonicalID
		if canonicalID == "" {
			canonicalID = r.ID
		}
		if _, dup := a.seen[canonicalID]; dup {
			continue
		}
		a.seen[canonicalID] = struct{}{}
		a.count++
		if severityRank(r.Severity.String) > severityRank(a.maxSeverity) {
			a.maxSeverity = r.Severity.String
		}
		switch strings.ToUpper(r.Severity.String) {
		case sevCritical:
			a.critical++
		case sevHigh:
			a.high++
		case sevMedium:
			a.medium++
		case sevLow:
			a.low++
		default:
			a.unknown++
		}
	}
	for i := range items {
		if items[i].Purl == nil {
			continue
		}
		if a := byPurl[*items[i].Purl]; a != nil {
			items[i].VulnCount = a.count
			items[i].MaxSeverity = a.maxSeverity
			items[i].CriticalCount = a.critical
			items[i].HighCount = a.high
			items[i].MediumCount = a.medium
			items[i].LowCount = a.low
			items[i].UnknownCount = a.unknown
		}
	}
	return nil
}

// severityRank orders severity labels for max comparison.
func severityRank(s string) int {
	switch s {
	case sevCritical:
		return 4
	case sevHigh:
		return 3
	case sevMedium:
		return 2
	case sevLow:
		return 1
	default:
		return 0
	}
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

	if err := decorateComponentVulns(ctx, q, sbomID, items); err != nil {
		return nil, err
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

	if err := decorateComponentVulns(ctx, q, sbomID, items); err != nil {
		return CursorPage[ComponentSummary]{}, err
	}

	return CursorPage[ComponentSummary]{Data: items, HasMore: hasMore}, nil
}
