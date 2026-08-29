package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/names"
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
	//
	// Malformed provenance JSON is log-and-degrade, not a hard error: it's
	// enricher output, not user input, so one bad enrichment row shouldn't
	// fail the whole SBOM detail request. See also recordProvenanceDrift in
	// internal/enrichment/provenance_drift.go, which applies the same policy.
	var signingProv provenance.Provenance
	if raw, hasProvenance := detail.Enrichments[names.Provenance]; hasProvenance {
		if err := json.Unmarshal(raw, &signingProv); err != nil {
			slog.ErrorContext(ctx, "parsing provenance enrichment", "sbom_id", id, "err", err)
		} else {
			drift, err := lookupProvenanceDrift(ctx, q, id)
			if err != nil {
				return SBOMDetail{}, err
			}
			detail.ProvenanceDrift = currentDrift(drift, provenance.SigningStatus(signingProv))
		}
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
		if e.Status != names.StatusSuccess || len(e.Data) == 0 {
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

// currentDrift returns drift only if it still describes the SBOM's present
// signing status. A regression event becomes stale once the status changes
// again — including a recovery, which recordProvenanceDrift does not itself
// record as a new event — and surfacing it then would show a banner that
// contradicts the current status.
func currentDrift(drift *ProvenanceDriftSummary, currentStatus string) *ProvenanceDriftSummary {
	if drift == nil || drift.NewStatus != currentStatus {
		return nil
	}
	return drift
}

// ListSBOMDriftHistory returns the provenance drift event history for an
// SBOM, newest first. Visibility-gated the same way as GetSBOM.
func (s *searchService) ListSBOMDriftHistory(ctx context.Context, sbomID pgtype.UUID, page DriftPage, vis VisibilityFilter) (CursorPage[ProvenanceDriftSummary], error) {
	q := repository.New(s.db)

	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      sbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CursorPage[ProvenanceDriftSummary]{}, ErrNotFound
		}
		return CursorPage[ProvenanceDriftSummary]{}, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return CursorPage[ProvenanceDriftSummary]{}, ErrNotFound
	}

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListProvenanceDriftBySBOM(ctx, repository.ListProvenanceDriftBySBOMParams{
		SbomID:           sbomID,
		HasCursor:        pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorDetectedAt: pgtype.Timestamptz{Time: page.CursorDetectedAt, Valid: page.HasCursor},
		CursorID:         uuidOrNull(page.CursorID),
		RowLimit:         page.Limit + 1,
	})
	if err != nil {
		return CursorPage[ProvenanceDriftSummary]{}, fmt.Errorf("listing sbom drift history: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	items := make([]ProvenanceDriftSummary, len(rows))
	for i, r := range rows {
		items[i] = ProvenanceDriftSummary{
			ID:             uuidToString(r.ID),
			PreviousStatus: r.PreviousStatus,
			NewStatus:      r.NewStatus,
			Reason:         r.Reason,
			DetectedAt:     r.DetectedAt.Time,
		}
	}
	return CursorPage[ProvenanceDriftSummary]{Data: items, HasMore: hasMore}, nil
}

// ListRecentProvenanceDrift returns the most recent provenance drift events
// visible to the caller, newest first. An admin sees every namespace; anyone
// else sees drift on the artifacts in their own and public namespaces, which
// is what makes the feed usable without the admin role.
func (s *searchService) ListRecentProvenanceDrift(ctx context.Context, page DriftPage, vis VisibilityFilter) (CursorPage[RecentDriftEntry], error) {
	q := repository.New(s.db)

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListRecentProvenanceDrift(ctx, repository.ListRecentProvenanceDriftParams{
		HasCursor:        pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorDetectedAt: pgtype.Timestamptz{Time: page.CursorDetectedAt, Valid: page.HasCursor},
		CursorID:         uuidOrNull(page.CursorID),
		IsAdmin:          vis.adminFlag(),
		UserID:           vis.UserID,
		OwnedOnly:        vis.ownedFlag(),
		RowLimit:         page.Limit + 1,
	})
	if err != nil {
		return CursorPage[RecentDriftEntry]{}, fmt.Errorf("listing recent provenance drift: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	items := make([]RecentDriftEntry, len(rows))
	for i, r := range rows {
		items[i] = RecentDriftEntry{
			ProvenanceDriftSummary: ProvenanceDriftSummary{
				ID:             uuidToString(r.ID),
				PreviousStatus: r.PreviousStatus,
				NewStatus:      r.NewStatus,
				Reason:         r.Reason,
				DetectedAt:     r.DetectedAt.Time,
			},
			SBOMID:       uuidToString(r.SbomID),
			RegistryID:   uuidToPtr(r.SourceID),
			RegistryName: textToPtr(r.SourceName),
			ArtifactID:   uuidToPtr(r.ArtifactID),
			ArtifactName: textToPtr(r.ArtifactName),
			ArtifactType: textToPtr(r.ArtifactType),
		}
	}
	return CursorPage[RecentDriftEntry]{Data: items, HasMore: hasMore}, nil
}

// ListOwnedActivity returns the SBOMs that landed in namespaces the given user
// owns, newest first — the ingest stream for their workspace (ocidex-998g.2).
//
// This takes an owner ID rather than a VisibilityFilter on purpose. Every other
// feed asks "what may this caller see", and answers with public rows included;
// this one asks "what happened in my namespaces", where somebody else's public
// namespace is not an answer. Passing a filter here would invite the wrong one.
func (s *searchService) ListOwnedActivity(ctx context.Context, ownerID pgtype.UUID, page FeedPage) (CursorPage[ActivityEntry], error) {
	if !ownerID.Valid {
		return CursorPage[ActivityEntry]{Data: []ActivityEntry{}}, nil
	}
	q := repository.New(s.db)

	// Fetch one extra row to detect whether a further page exists.
	rows, err := q.ListOwnedActivity(ctx, repository.ListOwnedActivityParams{
		OwnerID:         ownerID,
		HasCursor:       pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorCreatedAt: pgtype.Timestamptz{Time: page.CursorCreatedAt, Valid: page.HasCursor},
		CursorID:        uuidOrNull(page.CursorID),
		RowLimit:        page.Limit + 1,
	})
	if err != nil {
		return CursorPage[ActivityEntry]{}, fmt.Errorf("listing workspace activity: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	items := make([]ActivityEntry, len(rows))
	for i, r := range rows {
		items[i] = ActivityEntry{
			SBOMID:         uuidToString(r.ID),
			Digest:         textToPtr(r.Digest),
			SubjectVersion: textToPtr(r.SubjectVersion),
			CreatedAt:      r.CreatedAt.Time,
			NamespaceID:    uuidToString(r.NamespaceID),
			NamespaceName:  r.NamespaceName,
			SourceID:       uuidToPtr(r.SourceID),
			SourceName:     textToPtr(r.SourceName),
			SourceKind:     textToPtr(r.SourceKind),
			ArtifactID:     uuidToPtr(r.ArtifactID),
			ArtifactName:   textToPtr(r.ArtifactName),
			ArtifactType:   textToPtr(r.ArtifactType),
		}
	}
	return CursorPage[ActivityEntry]{Data: items, HasMore: hasMore}, nil
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

// ListSBOMVulns returns one page of the SBOM's vulnerability list, keyed by
// canonical_id so an alias group is a single finding, with the affected
// components attached inline.
func (s *searchService) ListSBOMVulns(ctx context.Context, sbomID pgtype.UUID, params SBOMVulnParams, vis VisibilityFilter) (PagedResult[SBOMVulnEntry], error) {
	q := repository.New(s.db)

	// Access check.
	visible, err := q.IsSBOMVisible(ctx, repository.IsSBOMVisibleParams{
		ID:      sbomID,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PagedResult[SBOMVulnEntry]{}, ErrNotFound
		}
		return PagedResult[SBOMVulnEntry]{}, fmt.Errorf("checking sbom visibility: %w", err)
	}
	if !visible {
		return PagedResult[SBOMVulnEntry]{}, ErrNotFound
	}

	limit, offset := clampPage(params.Limit, params.Offset)
	severity := optionalText(params.Severity)

	total, err := q.CountSBOMVulns(ctx, repository.CountSBOMVulnsParams{
		SbomID:   sbomID,
		Severity: severity,
	})
	if err != nil {
		return PagedResult[SBOMVulnEntry]{}, fmt.Errorf("counting sbom vulnerabilities: %w", err)
	}

	sortBy, sortDir := clampSort(params.SortBy, params.SortDir, SBOMVulnSortKeys)
	rows, err := q.ListSBOMVulns(ctx, repository.ListSBOMVulnsParams{
		SbomID:   sbomID,
		Severity: severity,
		SortBy:   sortBy,
		SortDir:  sortDir,
		Limit:    pgtype.Int4{Int32: limit, Valid: true},
		Offset:   pgtype.Int4{Int32: offset, Valid: true},
	})
	if err != nil {
		return PagedResult[SBOMVulnEntry]{}, fmt.Errorf("listing sbom vulnerabilities: %w", err)
	}

	items := make([]SBOMVulnEntry, len(rows))
	canonicalIDs := make([]string, len(rows))
	for i, r := range rows {
		canonicalIDs[i] = r.CanonicalID
		e := SBOMVulnEntry{
			ID:                   r.ID,
			CanonicalID:          r.CanonicalID,
			Severity:             severityOrUnknown(r.Severity),
			CvssScore:            float4ToPtr(r.CvssScore),
			AffectedPackageCount: r.AffectedPackageCount,
			AffectedPackages:     []SBOMVulnPackage{},
		}
		if r.Summary.Valid {
			e.Summary = &r.Summary.String
		}
		items[i] = e
	}

	if len(canonicalIDs) > 0 {
		if err := attachSBOMVulnPackages(ctx, q, sbomID, canonicalIDs, items); err != nil {
			return PagedResult[SBOMVulnEntry]{}, err
		}
	}

	return PagedResult[SBOMVulnEntry]{Data: items, Total: total, Limit: limit, Offset: offset}, nil
}

// attachSBOMVulnPackages fills in the AffectedPackages of one page of findings
// with a single query, rather than one per row.
func attachSBOMVulnPackages(ctx context.Context, q *repository.Queries, sbomID pgtype.UUID, canonicalIDs []string, items []SBOMVulnEntry) error {
	rows, err := q.ListSBOMVulnAffectedPackages(ctx, repository.ListSBOMVulnAffectedPackagesParams{
		SbomID:       sbomID,
		CanonicalIds: canonicalIDs,
	})
	if err != nil {
		return fmt.Errorf("listing affected packages: %w", err)
	}

	byCanonical := make(map[string][]SBOMVulnPackage, len(canonicalIDs))
	for _, r := range rows {
		p := SBOMVulnPackage{
			Purl:             r.Purl,
			Name:             r.Name,
			MatchedViaSource: r.MatchedViaSource.Bool,
		}
		if r.GroupName.Valid {
			p.Group = &r.GroupName.String
		}
		if r.Version.Valid {
			p.Version = &r.Version.String
		}
		// fixed_version arrives as interface{} because it comes out of an
		// array_agg subscript, the same way ListVulnsByPurl's does.
		if fv, ok := r.FixedVersion.(string); ok && fv != "" {
			p.FixedVersion = &fv
		}
		byCanonical[r.CanonicalID] = append(byCanonical[r.CanonicalID], p)
	}
	for i := range items {
		if pkgs := byCanonical[items[i].CanonicalID]; pkgs != nil {
			items[i].AffectedPackages = pkgs
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

	// The tree view renders a Vulns column from these nodes, exactly as the
	// component-list paths do, so the graph must carry the same decoration.
	if err := decorateComponentVulns(ctx, q, sbomID, nodes); err != nil {
		return DependencyGraph{}, err
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

// ListSBOMComponentsPage returns a page of an SBOM's components, ordered by
// (name, group_name, id) by default and by severity when the page asks for it.
// The ordering decides the pagination style: keyset for the default, offset for
// severity (ADR-043 rule 1 — see the query comment). Access is gated the same
// way as ListSBOMComponents.
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
		// The severity keys collapse to NULL when SortSeverity is false, so the
		// default ordering is unaffected and no second query is needed.
		SortSeverity: page.SortSeverity,
		SortDir:      sortDirSign(page.SortDesc),
		RowOffset:    page.Offset,
		RowLimit:     page.Limit + 1,
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
