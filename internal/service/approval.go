package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository"
)

// PendingActionTTL is how long a held agent write waits for a decision before
// it expires and can never run (ADR-0058 A4).
const PendingActionTTL = 24 * time.Hour

// Pending action statuses.
const (
	ActionPending  = "pending"
	ActionApproved = "approved"
	ActionDenied   = "denied"
	ActionExpired  = "expired"
	ActionExecuted = "executed"
	ActionFailed   = "failed"
)

// maxReasonLen caps the agent-supplied reason. It is untrusted display text,
// not data anything acts on.
const maxReasonLen = 500

// maxResultBody caps the stored response of an executed action.
const maxResultBody = 16 << 10

// ErrActionNotPending is returned when deciding an action that was already
// decided, ran, or expired.
var ErrActionNotPending = errors.New("action is no longer pending")

// PendingAction is one agent write held for a person's approval.
type PendingAction struct {
	ID           string
	APIKeyID     string
	UserID       string
	NamespaceID  string
	Capability   authz.Capability
	Method       string
	Path         string
	Body         []byte
	Effect       string
	Reason       string
	AgentLabel   string
	Status       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	DecidedBy    string
	DecidedAt    *time.Time
	ExecutedAt   *time.Time
	ResultStatus int
	ResultBody   string
}

// HoldRequest is what the API layer knows when it holds a request.
type HoldRequest struct {
	APIKeyID    string
	UserID      string
	NamespaceID string
	Capability  authz.Capability
	Method      string
	Path        string
	Body        []byte
	Effect      string
	Reason      string
	AgentLabel  string
}

// ApprovalService stores held agent writes and their decisions. Who may decide
// is the API layer's question (it holds the capability check); this service
// enforces only the state machine: pending -> approved|denied|expired, and
// approved -> executed|failed, each at most once.
type ApprovalService interface {
	Hold(ctx context.Context, req HoldRequest) (PendingAction, error)
	Get(ctx context.Context, id string) (PendingAction, error)
	ListFor(ctx context.Context, viewerID string, isAdmin bool, status string) ([]PendingAction, error)
	Decide(ctx context.Context, id, deciderID string, approve bool) (PendingAction, error)
	RecordResult(ctx context.Context, id string, status int, body []byte) (PendingAction, error)
	// ExecutingUser rebuilds the identity an approved action runs as: the key
	// that asked, re-read now so an expired or deleted key runs nothing.
	ExecutingUser(ctx context.Context, apiKeyID string) (AuthUser, error)
}

type approvalService struct {
	q         *repository.Queries
	publisher event.Publisher
}

// NewApprovalService returns an ApprovalService backed by pool.
func NewApprovalService(pool *pgxpool.Pool, publisher event.Publisher) ApprovalService {
	if publisher == nil {
		publisher = event.NopPublisher{}
	}
	return &approvalService{q: repository.New(pool), publisher: publisher}
}

func (s *approvalService) Hold(ctx context.Context, req HoldRequest) (PendingAction, error) {
	keyID, err := parseID(req.APIKeyID)
	if err != nil {
		return PendingAction{}, err
	}
	userID, err := parseID(req.UserID)
	if err != nil {
		return PendingAction{}, err
	}
	nsID, err := parseID(req.NamespaceID)
	if err != nil {
		return PendingAction{}, err
	}
	reason := req.Reason
	if len(reason) > maxReasonLen {
		reason = reason[:maxReasonLen]
	}
	body := req.Body
	if body == nil {
		body = []byte{}
	}
	row, err := s.q.CreatePendingAction(ctx, repository.CreatePendingActionParams{
		ApiKeyID:    keyID,
		UserID:      userID,
		NamespaceID: nsID,
		Capability:  string(req.Capability),
		Method:      req.Method,
		Path:        req.Path,
		Body:        body,
		Effect:      req.Effect,
		Reason:      pgtype.Text{String: reason, Valid: reason != ""},
		AgentLabel:  pgtype.Text{String: req.AgentLabel, Valid: req.AgentLabel != ""},
		ExpiresAt:   pgtype.Timestamptz{Time: time.Now().Add(PendingActionTTL), Valid: true},
	})
	if err != nil {
		return PendingAction{}, fmt.Errorf("holding action: %w", err)
	}
	a := toPendingAction(row)
	s.publisher.Publish(ctx, event.ApprovalRequested, event.ApprovalData{ActionID: row.ID, NamespaceID: nsID, Capability: string(a.Capability), Effect: a.Effect})
	return a, nil
}

func (s *approvalService) Get(ctx context.Context, id string) (PendingAction, error) {
	pid, err := parseID(id)
	if err != nil {
		return PendingAction{}, err
	}
	row, err := s.q.GetPendingAction(ctx, pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingAction{}, ErrNotFound
	}
	if err != nil {
		return PendingAction{}, fmt.Errorf("getting action: %w", err)
	}
	return s.expireIfDue(ctx, toPendingAction(row)), nil
}

func (s *approvalService) ListFor(ctx context.Context, viewerID string, isAdmin bool, status string) ([]PendingAction, error) {
	uid, err := parseID(viewerID)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListPendingActionsFor(ctx, repository.ListPendingActionsForParams{
		ViewerID: uid,
		IsAdmin:  isAdmin,
		Status:   pgtype.Text{String: status, Valid: status != ""},
	})
	if err != nil {
		return nil, fmt.Errorf("listing actions: %w", err)
	}
	out := make([]PendingAction, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.expireIfDue(ctx, toPendingAction(r)))
	}
	return out, nil
}

func (s *approvalService) Decide(ctx context.Context, id, deciderID string, approve bool) (PendingAction, error) {
	pid, err := parseID(id)
	if err != nil {
		return PendingAction{}, err
	}
	did, err := parseID(deciderID)
	if err != nil {
		return PendingAction{}, err
	}
	status := ActionDenied
	if approve {
		status = ActionApproved
	}
	row, err := s.q.DecidePendingAction(ctx, repository.DecidePendingActionParams{ID: pid, Status: status, DecidedBy: did})
	if errors.Is(err, pgx.ErrNoRows) {
		// Not pending, or expired: settle an overdue one so it reads as such.
		_ = s.q.ExpirePendingAction(ctx, pid)
		return PendingAction{}, ErrActionNotPending
	}
	if err != nil {
		return PendingAction{}, fmt.Errorf("deciding action: %w", err)
	}
	a := toPendingAction(row)
	typ := event.ApprovalDenied
	if approve {
		typ = event.ApprovalApproved
	}
	s.publisher.Publish(ctx, typ, event.ApprovalData{ActionID: row.ID, NamespaceID: row.NamespaceID, Capability: string(a.Capability), Effect: a.Effect, DecidedBy: did})
	return a, nil
}

func (s *approvalService) RecordResult(ctx context.Context, id string, status int, body []byte) (PendingAction, error) {
	pid, err := parseID(id)
	if err != nil {
		return PendingAction{}, err
	}
	outcome := ActionExecuted
	if status >= 400 {
		outcome = ActionFailed
	}
	if len(body) > maxResultBody {
		body = body[:maxResultBody]
	}
	row, err := s.q.RecordPendingActionResult(ctx, repository.RecordPendingActionResultParams{
		ID:           pid,
		Status:       outcome,
		ResultStatus: pgtype.Int4{Int32: int32(status), Valid: true}, //nolint:gosec // an HTTP status
		ResultBody:   pgtype.Text{String: string(body), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingAction{}, ErrActionNotPending
	}
	if err != nil {
		return PendingAction{}, fmt.Errorf("recording action result: %w", err)
	}
	a := toPendingAction(row)
	s.publisher.Publish(ctx, event.ApprovalExecuted, event.ApprovalData{ActionID: row.ID, NamespaceID: row.NamespaceID, Capability: string(a.Capability), Effect: a.Effect, ResultStatus: status})
	return a, nil
}

func (s *approvalService) ExecutingUser(ctx context.Context, apiKeyID string) (AuthUser, error) {
	kid, err := parseID(apiKeyID)
	if err != nil {
		return AuthUser{}, err
	}
	row, err := s.q.GetAPIKeyForExecution(ctx, kid)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthUser{}, ErrNotFound
	}
	if err != nil {
		return AuthUser{}, fmt.Errorf("loading key: %w", err)
	}
	return AuthUser{
		ID:                     row.UserID.String(),
		DisplayName:            displayName(row.DisplayName),
		Role:                   row.Role,
		APIKeyAuth:             true,
		APIKeyID:               row.ID.String(),
		APIKeyCaps:             validCapabilities(row.Capabilities),
		APIKeyClusterID:        row.ClusterID.String(),
		APIKeyKind:             row.Kind,
		APIKeyNamespaces:       uuidStrings(row.NamespaceIds),
		APIKeyAgentLabel:       row.AgentLabel.String,
		APIKeyApprovalRequired: validCapabilities(row.ApprovalRequired),
	}, nil
}

// expireIfDue settles a pending action whose time has passed, so every read
// reports it as expired rather than waiting for a sweeper.
func (s *approvalService) expireIfDue(ctx context.Context, a PendingAction) PendingAction {
	if a.Status != ActionPending || time.Now().Before(a.ExpiresAt) {
		return a
	}
	if pid, err := parseID(a.ID); err == nil {
		_ = s.q.ExpirePendingAction(ctx, pid)
	}
	a.Status = ActionExpired
	return a
}

// validCapabilities keeps the capability names this build knows. An unknown
// one can only come from a newer build, and a key must narrow, never fail open.
func validCapabilities(names []string) []authz.Capability {
	out := make([]authz.Capability, 0, len(names))
	for _, n := range names {
		if c := authz.Capability(n); c.Valid() {
			out = append(out, c)
		}
	}
	return out
}

func toPendingAction(r repository.PendingAction) PendingAction {
	a := PendingAction{
		ID:          r.ID.String(),
		APIKeyID:    r.ApiKeyID.String(),
		UserID:      r.UserID.String(),
		NamespaceID: r.NamespaceID.String(),
		Capability:  authz.Capability(r.Capability),
		Method:      r.Method,
		Path:        r.Path,
		Body:        r.Body,
		Effect:      r.Effect,
		Reason:      r.Reason.String,
		AgentLabel:  r.AgentLabel.String,
		Status:      r.Status,
		CreatedAt:   r.CreatedAt.Time,
		ExpiresAt:   r.ExpiresAt.Time,
		ResultBody:  r.ResultBody.String,
	}
	if r.DecidedBy.Valid {
		a.DecidedBy = r.DecidedBy.String()
	}
	if r.DecidedAt.Valid {
		t := r.DecidedAt.Time
		a.DecidedAt = &t
	}
	if r.ExecutedAt.Valid {
		t := r.ExecutedAt.Time
		a.ExecutedAt = &t
	}
	if r.ResultStatus.Valid {
		a.ResultStatus = int(r.ResultStatus.Int32)
	}
	return a
}
