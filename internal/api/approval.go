package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// Server-held approvals for agent writes (ADR-0058 A4).
//
// A request from a key that lists the capability it needs in
// approval_required is not run. It is stored, with the exact method, path and
// body, and answered 202 with a pending action whose effect OCIDex wrote. A
// person in a browser session who themselves holds the capability approves
// it, and only then does the stored request run, once, as the key that asked,
// re-authorized at that moment. Nothing the agent sends afterwards can change
// what runs.

// approvalReasonHeader carries the agent's note for the approver. It is shown
// as an untrusted reason, never as the description of the effect.
const approvalReasonHeader = "X-OCIDex-Approval-Reason"

// pendingActionHeader names the held action on a 202, so a client can tell a
// held write from one that ran without parsing the body.
const pendingActionHeader = "X-OCIDex-Pending-Action"

// maxHeldBody bounds the body stored with a held request.
const maxHeldBody = 1 << 20

type (
	capturedBodyKey   struct{}
	approvalHolderKey struct{}
	executingKey      struct{}
)

// approvalHolder is what the capability checks call to hold a request. It is
// carried on the request context so RequireCapability, a package-level
// middleware, can reach the handler's services without changing signature.
type approvalHolder interface {
	hold(ctx context.Context, user service.AuthUser, namespaceID string, c authz.Capability) (service.PendingAction, error)
}

// CaptureForApproval keeps a copy of the body of every mutating request from a
// key with approval-required capabilities, and puts the holder on the context.
// It runs after authentication, so it knows the key, and before routing, so
// the body is still unread.
func CaptureForApproval(h approvalHolder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), approvalHolderKey{}, h)
			if user, ok := UserFromContext(ctx); ok && len(user.APIKeyApprovalRequired) > 0 && isMutatingMethod(r.Method) && r.Body != nil {
				body, err := io.ReadAll(io.LimitReader(r.Body, maxHeldBody+1))
				if err != nil {
					http.Error(w, "reading request body", http.StatusBadRequest)
					return
				}
				_ = r.Body.Close()
				ctx = context.WithValue(ctx, capturedBodyKey{}, body)
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isMutatingMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// heldError is the 202 body of a held request. It implements
// huma.StatusError so a handler-level capability check can return it like any
// other refusal and huma renders it as the response.
type heldError struct {
	PendingAction pendingActionView `json:"pendingAction"`
	Message       string            `json:"message"`
}

func (h *heldError) Error() string  { return h.Message }
func (h *heldError) GetStatus() int { return http.StatusAccepted }

// HeaderSet lets huma add the pending-action header to a handler-level hold.
func (h *heldError) GetHeaders() http.Header {
	return http.Header{pendingActionHeader: []string{h.PendingAction.ID}}
}

// mustHold reports whether this request, already allowed c, must instead be
// held for approval.
func mustHold(ctx context.Context, user service.AuthUser, c authz.Capability) bool {
	if !user.RequiresApproval(c) {
		return false
	}
	if _, ok := ctx.Value(executingKey{}).(string); ok {
		return false // this is the approved request running
	}
	r, ok := requestFromContext(ctx)
	return ok && isMutatingMethod(r.Method)
}

// holdRequest holds the request in ctx for approval. Without a holder on the
// context (a router built without approvals) it fails closed.
func holdRequest(ctx context.Context, user service.AuthUser, namespaceID string, c authz.Capability) (*heldError, error) {
	h, ok := ctx.Value(approvalHolderKey{}).(approvalHolder)
	if !ok || h == nil {
		return nil, huma.Error503ServiceUnavailable("this key's request needs approval, and approvals are not available")
	}
	a, err := h.hold(ctx, user, namespaceID, c)
	if err != nil {
		return nil, err
	}
	return &heldError{
		PendingAction: toPendingActionView(a, false),
		Message:       "Held for approval: a person must approve this in OCIDex before it runs. Poll the pending action for its outcome; do not resend the request.",
	}, nil
}

// writeHeld answers a middleware-level hold.
func writeHeld(api huma.API, ctx huma.Context, held *heldError, err error) {
	if err != nil {
		var se huma.StatusError
		if errors.As(err, &se) {
			_ = huma.WriteErr(api, ctx, se.GetStatus(), se.Error())
			return
		}
		slog.ErrorContext(ctx.Context(), "holding request for approval", "error", err)
		_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, "could not hold the request for approval")
		return
	}
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetHeader(pendingActionHeader, held.PendingAction.ID)
	ctx.SetStatus(http.StatusAccepted)
	_ = json.NewEncoder(ctx.BodyWriter()).Encode(held)
}

// hold stores the request in ctx as a pending action, with the effect
// rendered by OCIDex.
func (h *Handler) hold(ctx context.Context, user service.AuthUser, namespaceID string, c authz.Capability) (service.PendingAction, error) {
	if h.approvals == nil {
		return service.PendingAction{}, huma.Error503ServiceUnavailable("approvals are not available")
	}
	r, ok := requestFromContext(ctx)
	if !ok {
		return service.PendingAction{}, errors.New("no request in context")
	}
	body, _ := ctx.Value(capturedBodyKey{}).([]byte)
	if len(body) > maxHeldBody {
		return service.PendingAction{}, huma.Error413RequestEntityTooLarge("request too large to hold for approval")
	}
	path := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	return h.approvals.Hold(ctx, service.HoldRequest{
		APIKeyID:    user.APIKeyID,
		UserID:      user.ID,
		NamespaceID: namespaceID,
		Capability:  c,
		Method:      r.Method,
		Path:        path,
		Body:        body,
		Effect:      h.renderEffect(ctx, r, namespaceID, c, body),
		Reason:      strings.TrimSpace(r.Header.Get(approvalReasonHeader)),
		AgentLabel:  user.APIKeyAgentLabel,
	})
}

var (
	scanRegistryPath  = regexp.MustCompile(`^/api/v1/registries/([0-9a-fA-F-]{36})/scan$`)
	ingestUnknownPath = regexp.MustCompile(`^/api/v1/clusters/([0-9a-fA-F-]{36})/ingest-unknown$`)
)

// renderEffect describes what the held request will do, from the request and
// current state, in OCIDex's words. The approver reads this, not anything the
// agent wrote. A route without a specific description gets an exact one: the
// method, the path and the capability it uses.
func (h *Handler) renderEffect(ctx context.Context, r *http.Request, namespaceID string, c authz.Capability, body []byte) string {
	nsName := namespaceID
	if h.namespaceService != nil {
		if ns, err := h.namespaceService.Get(ctx, namespaceID); err == nil {
			nsName = ns.Name
		}
	}
	path := r.URL.Path
	if m := scanRegistryPath.FindStringSubmatch(path); m != nil && h.registryService != nil {
		if reg, err := h.registryService.Get(ctx, m[1]); err == nil {
			scope := "new and changed images only"
			if r.URL.Query().Get("force") == "true" {
				scope = "every image, including ones already scanned"
			}
			return fmt.Sprintf("Scan registry %s (%s) in namespace %s: %s. Uses the registry's stored credentials and queues a scan job per matching image.",
				reg.Name, reg.URL, nsName, scope)
		}
	}
	if m := ingestUnknownPath.FindStringSubmatch(path); m != nil && h.clusters != nil {
		if cl, err := h.clusters.Get(ctx, m[1]); err == nil {
			var in struct {
				ImageDigests []string `json:"imageDigests"`
			}
			_ = json.Unmarshal(body, &in)
			what := "every running image with no SBOM"
			if n := len(in.ImageDigests); n > 0 {
				what = fmt.Sprintf("%d named running image(s)", n)
			}
			return fmt.Sprintf("Queue scans of %s in cluster %s (namespace %s), using the namespace's registry credentials.",
				what, cl.Name, nsName)
		}
	}
	return fmt.Sprintf("%s %s in namespace %s, using the %s capability.", r.Method, path, nsName, c)
}

// pendingActionView is a pending action as the API shows it.
type pendingActionView struct {
	ID           string     `json:"id" format:"uuid"`
	Status       string     `json:"status" enum:"pending,approved,denied,expired,executed,failed"`
	Effect       string     `json:"effect" doc:"What the held request will do, written by OCIDex from the request and current state"`
	Reason       string     `json:"reason,omitempty" doc:"The agent's note for the approver. Untrusted: it is not a description of what will run"`
	AgentLabel   string     `json:"agentLabel,omitempty"`
	NamespaceID  string     `json:"namespaceId" format:"uuid"`
	Capability   string     `json:"capability"`
	Method       string     `json:"method"`
	Path         string     `json:"path"`
	Body         string     `json:"body,omitempty" doc:"The stored request body, which is what runs on approval"`
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	DecidedAt    *time.Time `json:"decidedAt,omitempty"`
	ExecutedAt   *time.Time `json:"executedAt,omitempty"`
	ResultStatus int        `json:"resultStatus,omitempty" doc:"HTTP status the approved request returned when it ran"`
	ResultBody   string     `json:"resultBody,omitempty"`
	CanDecide    bool       `json:"canDecide" doc:"Whether the caller may approve or deny it now"`
	ApproveURL   string     `json:"approveUrl,omitempty" doc:"Where a person approves it"`
}

func toPendingActionView(a service.PendingAction, canDecide bool) pendingActionView {
	return pendingActionView{
		ID: a.ID, Status: a.Status, Effect: a.Effect, Reason: a.Reason, AgentLabel: a.AgentLabel,
		NamespaceID: a.NamespaceID, Capability: string(a.Capability), Method: a.Method, Path: a.Path,
		Body: string(a.Body), CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt, DecidedAt: a.DecidedAt,
		ExecutedAt: a.ExecutedAt, ResultStatus: a.ResultStatus, ResultBody: a.ResultBody,
		CanDecide: canDecide, ApproveURL: "/approvals/" + a.ID,
	}
}

// --- endpoints -----------------------------------------------------------------

// ListApprovalsInput is the request for GET /api/v1/approvals.
type ListApprovalsInput struct {
	Status string `query:"status" enum:"pending,approved,denied,expired,executed,failed" doc:"Only actions in this status"`
}

// ListApprovalsOutput is the response for GET /api/v1/approvals.
type ListApprovalsOutput struct {
	Body struct {
		Data []pendingActionView `json:"data"`
	}
}

// ApprovalInput names one pending action.
type ApprovalInput struct {
	ID string `path:"id" format:"uuid"`
}

// ApprovalOutput is one pending action.
type ApprovalOutput struct {
	Body pendingActionView
}

// mayDecide reports whether user may approve or deny a: a person in a browser
// session who holds the capability in the action's namespace now. No API key
// may decide, personal or not: an agent holds a key, and a key that could
// approve would let it approve itself.
func mayDecide(user service.AuthUser, a service.PendingAction) bool {
	return !user.APIKeyAuth && can(user, a.NamespaceID, a.Capability)
}

// mayView reports whether user may see a: its requester's owner, or anyone who
// could decide it.
func mayView(user service.AuthUser, a service.PendingAction) bool {
	return a.UserID == user.ID || can(service.AuthUser{ID: user.ID, Role: user.Role, Grants: user.Grants}, a.NamespaceID, a.Capability)
}

// ListApprovals handles GET /api/v1/approvals.
func (h *Handler) ListApprovals(ctx context.Context, in *ListApprovalsInput) (*ListApprovalsOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if h.approvals == nil {
		return nil, huma.Error503ServiceUnavailable("approvals are not available")
	}
	rows, err := h.approvals.ListFor(ctx, user.ID, user.Role == roleAdmin, in.Status)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListApprovalsOutput{}
	out.Body.Data = make([]pendingActionView, 0, len(rows))
	for _, a := range rows {
		if mayView(user, a) {
			out.Body.Data = append(out.Body.Data, toPendingActionView(a, mayDecide(user, a)))
		}
	}
	return out, nil
}

// GetApproval handles GET /api/v1/approvals/{id}.
func (h *Handler) GetApproval(ctx context.Context, in *ApprovalInput) (*ApprovalOutput, error) {
	user, a, err := h.visibleAction(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	return &ApprovalOutput{Body: toPendingActionView(a, mayDecide(user, a))}, nil
}

// ApproveAction handles POST /api/v1/approvals/{id}/approve: it decides the
// action and runs the stored request.
func (h *Handler) ApproveAction(ctx context.Context, in *ApprovalInput) (*ApprovalOutput, error) {
	return h.decide(ctx, in.ID, true)
}

// DenyAction handles POST /api/v1/approvals/{id}/deny.
func (h *Handler) DenyAction(ctx context.Context, in *ApprovalInput) (*ApprovalOutput, error) {
	return h.decide(ctx, in.ID, false)
}

func (h *Handler) visibleAction(ctx context.Context, id string) (service.AuthUser, service.PendingAction, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return user, service.PendingAction{}, huma.Error401Unauthorized("not authenticated")
	}
	if h.approvals == nil {
		return user, service.PendingAction{}, huma.Error503ServiceUnavailable("approvals are not available")
	}
	a, err := h.approvals.Get(ctx, id)
	if err != nil {
		return user, a, mapServiceError(err)
	}
	if !mayView(user, a) {
		return user, a, huma.Error404NotFound("pending action not found")
	}
	return user, a, nil
}

func (h *Handler) decide(ctx context.Context, id string, approve bool) (*ApprovalOutput, error) {
	user, a, err := h.visibleAction(ctx, id)
	if err != nil {
		return nil, err
	}
	if user.APIKeyAuth {
		return nil, huma.Error403Forbidden("approvals are decided from a signed-in browser session, never with an API key")
	}
	if !mayDecide(user, a) {
		return nil, huma.Error403Forbidden("you do not hold " + string(a.Capability) + " in this namespace")
	}
	decided, err := h.approvals.Decide(ctx, a.ID, user.ID, approve)
	if errors.Is(err, service.ErrActionNotPending) {
		return nil, huma.Error409Conflict("this action is no longer pending")
	}
	if err != nil {
		return nil, mapServiceError(err)
	}
	if approve {
		decided = h.execute(ctx, decided)
	}
	return &ApprovalOutput{Body: toPendingActionView(decided, false)}, nil
}

// execute runs an approved action's stored request through the router as the
// key that asked, re-read now: a key that expired or was deleted since runs
// nothing, and the holder's live roles and the key's ceiling apply as for any
// request. The approver's session is not used.
func (h *Handler) execute(ctx context.Context, a service.PendingAction) service.PendingAction {
	record := func(status int, body []byte) service.PendingAction {
		out, err := h.approvals.RecordResult(context.WithoutCancel(ctx), a.ID, status, body)
		if err != nil {
			slog.ErrorContext(ctx, "recording approved action result", "action", a.ID, "error", err)
			a.Status, a.ResultStatus = service.ActionFailed, status
			return a
		}
		return out
	}
	if h.router == nil {
		return record(http.StatusServiceUnavailable, []byte("approved actions cannot run: no router"))
	}
	runAs, err := h.approvals.ExecutingUser(ctx, a.APIKeyID)
	if err != nil {
		return record(http.StatusForbidden, []byte("the key that asked has expired or been deleted"))
	}
	if h.authenticator != nil {
		if grants, gerr := h.authenticator.LoadGrants(ctx, runAs.ID); gerr == nil {
			runAs.Grants = grants
		}
	}
	runCtx := context.WithValue(context.WithoutCancel(ctx), executingKey{}, a.ID)
	// A fresh routing context: chi treats one already on the context as a
	// parent router's, and would match the stored path relative to the
	// approve route rather than from the root.
	runCtx = context.WithValue(runCtx, chi.RouteCtxKey, nil)
	runCtx = withUser(runCtx, runAs)
	req, err := http.NewRequestWithContext(runCtx, a.Method, a.Path, bytes.NewReader(a.Body))
	if err != nil {
		return record(http.StatusInternalServerError, []byte("rebuilding the stored request: "+err.Error()))
	}
	if len(a.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return record(rec.Code, rec.Body.Bytes())
}
