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
