package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// KeyActivity is one recorded request by an agent key (ADR-0058 A5).
type KeyActivity struct {
	ID              int64
	OccurredAt      time.Time
	APIKeyID        string
	AgentLabel      string
	Tool            string
	Method          string
	Route           string
	Path            string
	Status          int
	PendingActionID string
}

// KeyActivityRecord is what the API layer records for one request.
type KeyActivityRecord struct {
	APIKeyID        string
	UserID          string
	AgentLabel      string
	Tool            string
	Method          string
	Route           string
	Path            string
	Status          int
	PendingActionID string
}

// KeyActivityService records and lists what agent keys did.
type KeyActivityService interface {
	Record(ctx context.Context, rec KeyActivityRecord) error
	// List returns one key's activity, newest first, before cursor (0 for the
	// first page). Only the key's holder, or an admin, sees any.
	List(ctx context.Context, apiKeyID, viewerID string, isAdmin bool, cursor int64, limit int32) ([]KeyActivity, error)
}

type keyActivityService struct{ q *repository.Queries }

// NewKeyActivityService returns a KeyActivityService backed by pool.
func NewKeyActivityService(pool *pgxpool.Pool) KeyActivityService {
	return &keyActivityService{q: repository.New(pool)}
}

func (s *keyActivityService) Record(ctx context.Context, rec KeyActivityRecord) error {
	keyID, err := parseID(rec.APIKeyID)
	if err != nil {
		return err
	}
	userID, err := parseID(rec.UserID)
	if err != nil {
		return err
	}
	var pending pgtype.UUID
	if rec.PendingActionID != "" {
		pending = uuidOrNull(rec.PendingActionID)
	}
	return s.q.RecordKeyActivity(ctx, repository.RecordKeyActivityParams{
		ApiKeyID:        keyID,
		UserID:          userID,
		AgentLabel:      pgtype.Text{String: rec.AgentLabel, Valid: rec.AgentLabel != ""},
		Tool:            pgtype.Text{String: rec.Tool, Valid: rec.Tool != ""},
		Method:          rec.Method,
		Route:           rec.Route,
		Path:            rec.Path,
		Status:          int32(rec.Status), //nolint:gosec // an HTTP status
		PendingActionID: pending,
	})
}

func (s *keyActivityService) List(ctx context.Context, apiKeyID, viewerID string, isAdmin bool, cursor int64, limit int32) ([]KeyActivity, error) {
	keyID, err := parseID(apiKeyID)
	if err != nil {
		return nil, err
	}
	viewer, err := parseID(viewerID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.q.ListKeyActivity(ctx, repository.ListKeyActivityParams{
		ApiKeyID: keyID, ViewerID: viewer, IsAdmin: isAdmin,
		HasCursor: cursor > 0, CursorID: cursor, RowLimit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("listing key activity: %w", err)
	}
	out := make([]KeyActivity, 0, len(rows))
	for _, r := range rows {
		a := KeyActivity{
			ID: r.ID, OccurredAt: r.OccurredAt.Time, APIKeyID: r.ApiKeyID.String(),
			AgentLabel: r.AgentLabel.String, Tool: r.Tool.String, Method: r.Method,
			Route: r.Route, Path: r.Path, Status: int(r.Status),
		}
		if r.PendingActionID.Valid {
			a.PendingActionID = r.PendingActionID.String()
		}
		out = append(out, a)
	}
	return out, nil
}
