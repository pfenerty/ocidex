package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// WatchService manages a user's artifact watchlist (ocidex-998g.3).
//
// A watch is a private bookmark, not an ownership or visibility relation:
// watching a public base image somebody else owns is the primary use case. The
// one place visibility matters is Watch, which refuses an artifact the caller
// cannot see — otherwise the watchlist would leak the existence of private
// artifacts to anyone willing to guess a UUID.
//
// Unwatch and List deliberately do not re-check visibility. A watch row that
// exists is a watch the user was entitled to create; re-filtering afterwards
// would produce a watch that silently vanishes when its artifact's namespace
// flips private, with no way for the user to see or clear it.
type WatchService interface {
	// Watch records a watch. It is idempotent, so an optimistic UI toggle can
	// replay a click without erroring. It returns ErrNotFound when the
	// artifact does not exist or is not visible to the caller.
	Watch(ctx context.Context, userID pgtype.UUID, artifactID string, vis VisibilityFilter) error
	// Unwatch removes a watch. Removing one that is not there is not an error,
	// for the same idempotency reason.
	Unwatch(ctx context.Context, userID pgtype.UUID, artifactID string) error
	// List returns the caller's watches, newest first.
	List(ctx context.Context, userID pgtype.UUID, page FeedPage) (CursorPage[WatchEntry], error)
	// Feed returns changes to the caller's watched artifacts, newest first.
	// Unlike List, it does apply vis — see the WatchEvent doc comment.
	Feed(ctx context.Context, userID pgtype.UUID, vis VisibilityFilter, page FeedPage) (CursorPage[WatchEvent], error)
}

// WatchEvent is one change to a watched artifact (ocidex-998g.4).
//
// None of the three signals is computed here. A new version is a sbom row, a
// drift event is a provenance_drift_events row, and a vulnerability is the same
// component→package_vulnerability→vulnerability join the SBOM and artifact vuln
// panels already use; the feed only scopes them to the watch set and merges
// them onto one timeline. Version events carry PreviousVersion so the UI can
// link to the existing changelog endpoint rather than restate the diff.
//
// The feed re-checks visibility even though the watchlist does not, and the
// asymmetry is deliberate: a watch is the user's own bookmark and survives its
// artifact going private, but the events are content. A since-privatised
// artifact therefore stays on the watchlist and stops producing feed entries.
type WatchEvent struct {
	// Kind is the discriminator: which of the optional fields below are
	// populated follows from it. Declared as an enum so the generated client
	// types narrow to the three values instead of a bare string.
	Kind         string    `json:"kind" enum:"new_version,drift,vulnerability"`
	ID           string    `json:"id"`
	OccurredAt   time.Time `json:"occurredAt"`
	ArtifactID   string    `json:"artifactId"`
	ArtifactName string    `json:"artifactName"`
	ArtifactType string    `json:"artifactType"`
	SBOMID       string    `json:"sbomId"`
	Version      *string   `json:"version,omitempty"`

	// New-version fields.
	PreviousVersion *string `json:"previousVersion,omitempty"`

	// Drift fields.
	PreviousStatus *string `json:"previousStatus,omitempty"`
	NewStatus      *string `json:"newStatus,omitempty"`
	Reason         *string `json:"reason,omitempty"`

	// Vulnerability fields.
	VulnerabilityID *string  `json:"vulnerabilityId,omitempty"`
	Severity        *string  `json:"severity,omitempty"`
	CVSSScore       *float32 `json:"cvssScore,omitempty"`
	Summary         *string  `json:"summary,omitempty"`
}

// WatchEntry is one watched artifact, plus when the watch was created so the UI
// can order and label the list.
type WatchEntry struct {
	ArtifactID string    `json:"artifactId"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Group      *string   `json:"group,omitempty"`
	Purl       *string   `json:"purl,omitempty"`
	SbomCount  int64     `json:"sbomCount"`
	WatchedAt  time.Time `json:"watchedAt"`
}

type watchService struct {
	repo repository.WatchRepository
}

// NewWatchService constructs a WatchService.
func NewWatchService(pool *pgxpool.Pool) WatchService {
	return &watchService{repo: repository.New(pool)}
}

func (s *watchService) Watch(ctx context.Context, userID pgtype.UUID, artifactID string, vis VisibilityFilter) error {
	id := uuidOrNull(artifactID)
	if !id.Valid || !userID.Valid {
		return ErrNotFound
	}

	// The visibility gate. artifact_visible() answers "does this artifact exist
	// and may this caller see it" in one query, so an invisible artifact and a
	// missing one are indistinguishable from outside — which is the point.
	visible, err := s.repo.IsArtifactVisible(ctx, repository.IsArtifactVisibleParams{
		AID:     id,
		UserID:  vis.UserID,
		IsAdmin: visAdminBool(vis),
	})
	if err != nil {
		return fmt.Errorf("checking artifact visibility: %w", err)
	}
	if !visible {
		return ErrNotFound
	}

	if err := s.repo.CreateArtifactWatch(ctx, repository.CreateArtifactWatchParams{
		UserID:     userID,
		ArtifactID: id,
	}); err != nil {
		return fmt.Errorf("creating artifact watch: %w", err)
	}
	return nil
}

func (s *watchService) Unwatch(ctx context.Context, userID pgtype.UUID, artifactID string) error {
	// Nothing could have been watched under an unparseable id, and the caller
	// asked for it to be gone. It is.
	id := uuidOrNull(artifactID)
	if !id.Valid || !userID.Valid {
		return nil
	}
	if _, err := s.repo.DeleteArtifactWatch(ctx, repository.DeleteArtifactWatchParams{
		UserID:     userID,
		ArtifactID: id,
	}); err != nil {
		return fmt.Errorf("deleting artifact watch: %w", err)
	}
	return nil
}

func (s *watchService) List(ctx context.Context, userID pgtype.UUID, page FeedPage) (CursorPage[WatchEntry], error) {
	if !userID.Valid {
		return CursorPage[WatchEntry]{Data: []WatchEntry{}}, nil
	}

	// Fetch one extra row to detect whether a further page exists.
	rows, err := s.repo.ListArtifactWatches(ctx, repository.ListArtifactWatchesParams{
		UserID:          userID,
		HasCursor:       pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorCreatedAt: pgtype.Timestamptz{Time: page.CursorCreatedAt, Valid: page.HasCursor},
		CursorID:        uuidOrNull(page.CursorID),
		RowLimit:        page.Limit + 1,
	})
	if err != nil {
		return CursorPage[WatchEntry]{}, fmt.Errorf("listing artifact watches: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	items := make([]WatchEntry, len(rows))
	for i, r := range rows {
		items[i] = WatchEntry{
			ArtifactID: uuidToString(r.ArtifactID),
			Type:       r.Type,
			Name:       r.Name,
			Group:      textToPtr(r.GroupName),
			Purl:       textToPtr(r.Purl),
			SbomCount:  r.SbomCount,
			WatchedAt:  r.CreatedAt.Time,
		}
	}
	return CursorPage[WatchEntry]{Data: items, HasMore: hasMore}, nil
}

func (s *watchService) Feed(ctx context.Context, userID pgtype.UUID, vis VisibilityFilter, page FeedPage) (CursorPage[WatchEvent], error) {
	if !userID.Valid {
		return CursorPage[WatchEvent]{Data: []WatchEvent{}}, nil
	}

	// One extra row, same as List, to detect a further page.
	rows, err := s.repo.ListWatchedArtifactEvents(ctx, repository.ListWatchedArtifactEventsParams{
		WatcherID:        userID,
		UserID:           vis.UserID,
		IsAdmin:          visAdminBool(vis),
		HasCursor:        pgtype.Bool{Bool: page.HasCursor, Valid: true},
		CursorOccurredAt: pgtype.Timestamptz{Time: page.CursorCreatedAt, Valid: page.HasCursor},
		CursorID:         uuidOrNull(page.CursorID),
		RowLimit:         page.Limit + 1,
	})
	if err != nil {
		return CursorPage[WatchEvent]{}, fmt.Errorf("listing watched artifact events: %w", err)
	}

	hasMore := len(rows) > int(page.Limit)
	if hasMore {
		rows = rows[:page.Limit]
	}

	items := make([]WatchEvent, len(rows))
	for i, r := range rows {
		items[i] = WatchEvent{
			Kind:            r.Kind,
			ID:              uuidToString(r.EventID),
			OccurredAt:      r.OccurredAt.Time,
			ArtifactID:      uuidToString(r.ArtifactID),
			ArtifactName:    r.ArtifactName,
			ArtifactType:    r.ArtifactType,
			SBOMID:          uuidToString(r.SbomID),
			Version:         textToPtr(r.SubjectVersion),
			PreviousVersion: emptyToNil(r.PreviousVersion),
			PreviousStatus:  textToPtr(r.PreviousStatus),
			NewStatus:       textToPtr(r.NewStatus),
			Reason:          textToPtr(r.Reason),
			VulnerabilityID: textToPtr(r.VulnID),
			Severity:        textToPtr(r.VulnSeverity),
			CVSSScore:       float4ToPtr(r.VulnCvssScore),
			Summary:         textToPtr(r.VulnSummary),
		}
	}
	return CursorPage[WatchEvent]{Data: items, HasMore: hasMore}, nil
}

// emptyToNil drops a sentinel empty string. The feed query COALESCEs the
// previous version to ” because sqlc reads its cast as non-null; the API
// contract is an omitted field, not a blank one.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
