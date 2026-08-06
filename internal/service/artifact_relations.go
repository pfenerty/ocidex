package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Artifact relationships (ADR-041).
//
// Relationships are derived at read time from component data; nothing is stored.
// The queries in db/queries/artifact_relations.sql match COARSELY on the purl
// base (or the type/name/group tuple) so an index can serve them; this file
// applies the EXACT match with componentKey — the same function
// internal/service/changelog.go uses for diff. That reuse is the whole point of
// ADR-041 R1: relationships and diff cannot disagree about what "the same
// package" means, because there is only one implementation of it.

// relationLimit caps rows fetched per direction. A relationship view is a
// summary, not a paginated listing; anything approaching this is a sign the
// identity key is matching far too broadly.
const relationLimit = 200

// ArtifactRelation is one derived edge between the subject artifact and another
// tracked artifact.
type ArtifactRelation struct {
	// Artifact is the other end of the relation: the container for a usage, the
	// contained artifact for a "contains".
	ArtifactID    string  `json:"artifactId"`
	ArtifactType  string  `json:"artifactType"`
	ArtifactName  string  `json:"artifactName"`
	ArtifactGroup *string `json:"artifactGroup,omitempty"`

	// SBOMID is the SBOM the match was observed in: for usages, the containing
	// artifact's latest SBOM; for contains, the subject's own latest SBOM.
	SBOMID string `json:"sbomId"`
	// SubjectVersion, Digest and Flavor describe that SBOM's subject — i.e. which
	// build of the containing artifact was inspected. Empty for contains, where
	// the SBOM is the subject's own and adds nothing.
	SubjectVersion *string    `json:"subjectVersion,omitempty"`
	Digest         *string    `json:"digest,omitempty"`
	Flavor         *string    `json:"flavor,omitempty"`
	ObservedAt     *time.Time `json:"observedAt,omitempty"`

	// MatchedVersion is the version recorded on the matching component — the
	// version actually shipped. Nil when the SBOM recorded no version.
	MatchedVersion *string `json:"matchedVersion,omitempty"`
	// CurrentVersion is the counterpart artifact's own latest subject_version.
	CurrentVersion *string `json:"currentVersion,omitempty"`
	// IsCurrent reports whether MatchedVersion equals CurrentVersion. Nil when
	// either side is unknown — "we cannot tell" is not the same as "no drift",
	// and collapsing them would report false confidence (ADR-041 R2).
	IsCurrent *bool `json:"isCurrent,omitempty"`
}

// GetArtifactUsages returns the tracked artifacts whose latest visible SBOM
// contains a component matching this artifact — "where does this ship?".
//
// CurrentVersion on every returned relation is the SUBJECT's current version,
// so IsCurrent answers "does this container ship the current build of me?".
func (s *searchService) GetArtifactUsages(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) ([]ArtifactRelation, error) {
	q := repository.New(s.db)

	subject, err := s.visibleArtifact(ctx, q, artifactID, vis)
	if err != nil {
		return nil, err
	}
	subjectKey := componentKey(subject.Type, subject.Name, subject.GroupName, subject.Purl)

	current, err := q.GetArtifactCurrentVersion(ctx, repository.GetArtifactCurrentVersionParams{
		ArtifactID: artifactID,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("getting artifact current version: %w", err)
	}

	rows, err := q.ListArtifactUsages(ctx, repository.ListArtifactUsagesParams{
		PurlBase:     purlBaseParam(subject.Purl),
		SubjectType:  subject.Type,
		SubjectName:  subject.Name,
		SubjectGroup: textOrEmpty(subject.GroupName),
		ArtifactID:   artifactID,
		UserID:       vis.UserID,
		IsAdmin:      visAdminBool(vis),
		RowLimit:     relationLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("listing artifact usages: %w", err)
	}

	out := make([]ArtifactRelation, 0, len(rows))
	for _, r := range rows {
		// Exact identity check. The SQL match was a superset — it ignored the
		// identity qualifiers ADR-019 Rule 1 keeps, so e.g. an arm64 build of the
		// same package reaches here and is rejected below.
		if componentKey(r.MatchedType, r.MatchedName, r.MatchedGroup, r.MatchedPurl) != subjectKey {
			continue
		}
		rel := ArtifactRelation{
			ArtifactID:     uuidToString(r.ArtifactID),
			ArtifactType:   r.ArtifactType,
			ArtifactName:   r.ArtifactName,
			ArtifactGroup:  textToPtr(r.ArtifactGroup),
			SBOMID:         uuidToString(r.SbomID),
			SubjectVersion: textToPtr(r.SubjectVersion),
			Digest:         textToPtr(r.Digest),
			Flavor:         textToPtr(r.Flavor),
			MatchedVersion: textToPtr(r.MatchedVersion),
			CurrentVersion: textToPtr(current),
		}
		if r.CreatedAt.Valid {
			t := r.CreatedAt.Time
			rel.ObservedAt = &t
		}
		rel.IsCurrent = sameVersion(rel.MatchedVersion, rel.CurrentVersion)
		out = append(out, rel)
	}
	return out, nil
}

// GetArtifactContains returns the tracked artifacts matched by components of
// this artifact's latest visible SBOM — "what of ours does this carry?".
//
// CurrentVersion here is each MATCHED artifact's own current version, so
// IsCurrent answers "does this container carry the current build of that?".
func (s *searchService) GetArtifactContains(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) ([]ArtifactRelation, error) {
	q := repository.New(s.db)

	if _, err := s.visibleArtifact(ctx, q, artifactID, vis); err != nil {
		return nil, err
	}

	rows, err := q.ListArtifactContains(ctx, repository.ListArtifactContainsParams{
		ArtifactID: artifactID,
		UserID:     vis.UserID,
		IsAdmin:    visAdminBool(vis),
		RowLimit:   relationLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("listing artifact contains: %w", err)
	}

	out := make([]ArtifactRelation, 0, len(rows))
	for _, r := range rows {
		// Both sides must produce the same key. The SQL join paired them on the
		// purl base alone, so qualifier-level differences are filtered here.
		if componentKey(r.MatchedType, r.MatchedName, r.MatchedGroup, r.MatchedPurl) !=
			componentKey(r.ArtifactType, r.ArtifactName, r.ArtifactGroup, r.ArtifactPurl) {
			continue
		}
		rel := ArtifactRelation{
			ArtifactID:     uuidToString(r.ArtifactID),
			ArtifactType:   r.ArtifactType,
			ArtifactName:   r.ArtifactName,
			ArtifactGroup:  textToPtr(r.ArtifactGroup),
			SBOMID:         uuidToString(r.CurrentSbomID),
			Digest:         textToPtr(r.CurrentDigest),
			Flavor:         textToPtr(r.CurrentFlavor),
			MatchedVersion: textToPtr(r.MatchedVersion),
			CurrentVersion: textToPtr(r.CurrentVersion),
		}
		rel.IsCurrent = sameVersion(rel.MatchedVersion, rel.CurrentVersion)
		out = append(out, rel)
	}
	return out, nil
}

// visibleArtifact resolves an artifact after an explicit visibility check,
// returning ErrNotFound rather than ErrForbidden so a caller cannot probe for
// the existence of artifacts in namespaces they cannot see (ADR-025).
func (s *searchService) visibleArtifact(
	ctx context.Context, q *repository.Queries, id pgtype.UUID, vis VisibilityFilter,
) (repository.GetArtifactRow, error) {
	visible, err := q.IsArtifactVisible(ctx, repository.IsArtifactVisibleParams{
		AID:     id,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		return repository.GetArtifactRow{}, fmt.Errorf("checking artifact visibility: %w", err)
	}
	if !visible {
		return repository.GetArtifactRow{}, ErrNotFound
	}

	row, err := q.GetArtifact(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.GetArtifactRow{}, ErrNotFound
		}
		return repository.GetArtifactRow{}, fmt.Errorf("getting artifact: %w", err)
	}
	return row, nil
}

// purlBaseParam derives the SQL-side coarse key from a purl, or an invalid Text
// (NULL) to select the query's tuple-fallback branch. It mirrors the leading
// half of normalizeComponentPurl: cut at '?' first, then at '@'. Qualifiers are
// deliberately dropped rather than filtered — narrowing to the identity set
// happens in Go, against the real key.
func purlBaseParam(purl pgtype.Text) pgtype.Text {
	if !purl.Valid || purl.String == "" {
		return pgtype.Text{}
	}
	path, _, _ := strings.Cut(purl.String, "?")
	return pgtype.Text{String: stripPurlVersion(path), Valid: true}
}

// textOrEmpty normalizes a nullable group to the ” the query compares against,
// matching COALESCE(group_name, ”) on the SQL side.
func textOrEmpty(t pgtype.Text) pgtype.Text {
	if !t.Valid {
		return pgtype.Text{String: "", Valid: true}
	}
	return pgtype.Text{String: t.String, Valid: true}
}

// sameVersion reports whether two optional versions match, or nil when
// either is absent. Nil means "unknown", not "differs".
func sameVersion(matched, current *string) *bool {
	if matched == nil || current == nil {
		return nil
	}
	eq := *matched == *current
	return &eq
}
