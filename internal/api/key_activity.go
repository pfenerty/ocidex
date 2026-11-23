package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// keyActivityRecorder is the part of KeyActivityService the middleware needs.
type keyActivityRecorder interface {
	Record(ctx context.Context, rec service.KeyActivityRecord) error
}

// statusRecorder remembers the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// RecordAgentActivity records every request an agent key makes that changes
// something or is refused (ADR-0058 A5): writes, holds, and 401/403/429.
// Successful reads are not recorded. Recording never fails the request.
func RecordAgentActivity(rec keyActivityRecorder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if rec == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok || user.APIKeyKind != service.KeyKindAgent {
				next.ServeHTTP(w, r)
				return
			}
			sw := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			refused := status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests
			if !isMutatingMethod(r.Method) && !refused {
				return
			}
			route := r.URL.Path
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				route = rc.RoutePattern()
			}
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
			defer cancel()
			if err := rec.Record(ctx, service.KeyActivityRecord{
				APIKeyID:        user.APIKeyID,
				UserID:          user.ID,
				AgentLabel:      user.APIKeyAgentLabel,
				Tool:            agentTool(r),
				Method:          r.Method,
				Route:           route,
				Path:            r.URL.EscapedPath(),
				Status:          status,
				PendingActionID: sw.Header().Get(pendingActionHeader),
			}); err != nil {
				slog.WarnContext(r.Context(), "recording agent key activity", "error", err)
			}
		})
	}
}

// KeyActivityInput is the request for GET /api/v1/auth/keys/{id}/activity.
type KeyActivityInput struct {
	ID     string `path:"id" format:"uuid" doc:"Key UUID"`
	Before int64  `query:"before" doc:"Return entries older than this entry id (the last id of the previous page)"`
	Limit  int32  `query:"limit" minimum:"1" maximum:"200" default:"50"`
}

// KeyActivityEntry is one recorded request by an agent key.
type KeyActivityEntry struct {
	ID              int64     `json:"id"`
	OccurredAt      time.Time `json:"occurredAt"`
	AgentLabel      string    `json:"agentLabel,omitempty"`
	Tool            string    `json:"tool,omitempty" doc:"The MCP tool the request came from, as the agent's MCP server reported it"`
	Method          string    `json:"method"`
	Route           string    `json:"route" doc:"The route pattern the request matched"`
	Path            string    `json:"path"`
	Status          int       `json:"status"`
	PendingActionID string    `json:"pendingActionId,omitempty" doc:"Set when the request was held for approval"`
}

// KeyActivityOutput is the response for GET /api/v1/auth/keys/{id}/activity.
type KeyActivityOutput struct {
	Body struct {
		Data []KeyActivityEntry `json:"data"`
	}
}

// ListKeyActivity handles GET /api/v1/auth/keys/{id}/activity.
func (h *Handler) ListKeyActivity(ctx context.Context, in *KeyActivityInput) (*KeyActivityOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if h.keyActivity == nil {
		return nil, huma.Error503ServiceUnavailable("key activity is not available")
	}
	isAdmin := user.Role == roleAdmin && user.KeyAllows(authz.CapInstallationAdmin)
	if !isAdmin {
		// Someone else's key is not found, not forbidden.
		if _, err := h.ownAPIKey(ctx, user, in.ID); err != nil {
			return nil, err
		}
	}
	rows, err := h.keyActivity.List(ctx, in.ID, user.ID, isAdmin, in.Before, in.Limit)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &KeyActivityOutput{}
	out.Body.Data = make([]KeyActivityEntry, 0, len(rows))
	for _, a := range rows {
		out.Body.Data = append(out.Body.Data, KeyActivityEntry{
			ID: a.ID, OccurredAt: a.OccurredAt, AgentLabel: a.AgentLabel, Tool: a.Tool, Method: a.Method,
			Route: a.Route, Path: a.Path, Status: a.Status, PendingActionID: a.PendingActionID,
		})
	}
	return out, nil
}
