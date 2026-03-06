package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	sessionCookieName = "ocidex_session"
	stateCookieName   = "ocidex_oauth_state"
	stateMaxAge       = 5 * time.Minute
)

// HandleLogin initiates GitHub OAuth flow.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)

	state, err := h.stateCookie.Encode("oauth-state", map[string]string{"nonce": nonceStr})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int(stateMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.Environment == "production",
	})

	http.Redirect(w, r, h.authService.BuildAuthURL(state), http.StatusTemporaryRedirect)
}

// HandleCallback handles the GitHub OAuth callback.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}

	// Clear the state cookie immediately.
	http.SetCookie(w, &http.Cookie{
		Name:    stateCookieName,
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})

	var stateData map[string]string
	if err := h.stateCookie.Decode("oauth-state", stateCookie.Value, &stateData); err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	user, err := h.authService.ExchangeCodeForUser(r.Context(), code)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	token, err := h.authService.CreateSession(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   h.cfg.SessionMaxAgeDays * 86400,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   h.cfg.Environment == "production",
	})

	http.Redirect(w, r, h.cfg.FrontendURL, http.StatusSeeOther)
}

// HandleLogout clears the session.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil {
		_ = h.authService.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookieName,
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
	w.WriteHeader(http.StatusNoContent)
}

// registerAuthOps registers raw chi routes and huma-managed auth endpoints.
func registerAuthOps(r chi.Router, api huma.API, h *Handler) {
	// Browser-redirect flows (not huma-managed).
	r.Get("/auth/login", h.HandleLogin)
	r.Get("/auth/callback", h.HandleCallback)
	r.Post("/auth/logout", h.HandleLogout)

	// Huma-managed endpoints.
	huma.Register(api, huma.Operation{
		OperationID: "get-me",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me",
		Summary:     "Get current user",
		Tags:        []string{"Auth"},
	}, h.GetMe)

	huma.Register(api, huma.Operation{
		OperationID:   "create-api-key",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/keys",
		Summary:       "Create API key",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
	}, h.CreateAPIKey)

	huma.Register(api, huma.Operation{
		OperationID: "list-api-keys",
		Method:      http.MethodGet,
		Path:        "/api/v1/auth/keys",
		Summary:     "List API keys",
		Tags:        []string{"Auth"},
	}, h.ListAPIKeys)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-api-key",
		Method:        http.MethodDelete,
		Path:          "/api/v1/auth/keys/{id}",
		Summary:       "Delete API key",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusNoContent,
	}, h.DeleteAPIKey)

	huma.Register(api, huma.Operation{
		OperationID: "list-users",
		Method:      http.MethodGet,
		Path:        "/api/v1/users",
		Summary:     "List users",
		Tags:        []string{"Auth"},
	}, h.ListUsers)

	huma.Register(api, huma.Operation{
		OperationID: "update-user-role",
		Method:      http.MethodPatch,
		Path:        "/api/v1/users/{id}/role",
		Summary:     "Update user role",
		Tags:        []string{"Auth"},
	}, h.UpdateUserRole)

	huma.Register(api, huma.Operation{
		OperationID: "get-system-status",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/status",
		Summary:     "Get system status",
		Tags:        []string{"Admin"},
	}, h.GetSystemStatus)
}

// ---------------------------------------------------------------------------
// Huma handlers
// ---------------------------------------------------------------------------

func (h *Handler) GetMe(ctx context.Context, _ *struct{}) (*MeOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	out := &MeOutput{}
	out.Body.ID = uuid.UUID(user.ID.Bytes).String()
	out.Body.GitHubUsername = user.GitHubUsername
	out.Body.Role = user.Role
	return out, nil
}

func (h *Handler) CreateAPIKey(ctx context.Context, in *CreateAPIKeyInput) (*CreateAPIKeyOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" && user.Role != "member" {
		return nil, huma.Error403Forbidden("insufficient role")
	}
	plaintext, err := h.authService.CreateAPIKey(ctx, user.ID, in.Body.Name)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("creating key: %v", err))
	}
	out := &CreateAPIKeyOutput{}
	out.Body.Key = plaintext
	return out, nil
}

func (h *Handler) ListAPIKeys(ctx context.Context, _ *struct{}) (*ListAPIKeysOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" && user.Role != "member" {
		return nil, huma.Error403Forbidden("insufficient role")
	}
	keys, err := h.authService.ListAPIKeys(ctx, user.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing keys: %v", err))
	}
	out := &ListAPIKeysOutput{}
	out.Body.Keys = make([]APIKeyMetaResponse, len(keys))
	for i, k := range keys {
		out.Body.Keys[i] = APIKeyMetaResponse{
			ID:         uuid.UUID(k.ID.Bytes).String(),
			Name:       k.Name,
			Prefix:     k.Prefix,
			CreatedAt:  k.CreatedAt,
			LastUsedAt: k.LastUsedAt,
		}
	}
	return out, nil
}

func (h *Handler) DeleteAPIKey(ctx context.Context, in *DeleteAPIKeyInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" && user.Role != "member" {
		return nil, huma.Error403Forbidden("insufficient role")
	}
	keyID, err := parseUUID(in.ID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid key id")
	}
	if err := h.authService.DeleteAPIKey(ctx, user.ID, keyID); err != nil {
		return nil, huma.Error404NotFound("key not found")
	}
	return nil, nil
}

func (h *Handler) ListUsers(ctx context.Context, _ *struct{}) (*ListUsersOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	users, err := h.authService.ListUsers(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing users: %v", err))
	}
	out := &ListUsersOutput{}
	out.Body.Users = make([]UserResponse, len(users))
	for i, u := range users {
		out.Body.Users[i] = UserResponse{
			ID:             uuid.UUID(u.ID.Bytes).String(),
			GitHubUsername: u.GitHubUsername,
			Role:           u.Role,
		}
	}
	return out, nil
}

func (h *Handler) UpdateUserRole(ctx context.Context, in *UpdateUserRoleInput) (*UpdateUserRoleOutput, error) {
	caller, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if caller.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	targetID, err := parseUUID(in.ID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid user id")
	}
	u, err := h.authService.UpdateUserRole(ctx, targetID, in.Body.Role)
	if err != nil {
		return nil, huma.Error400BadRequest(fmt.Sprintf("updating role: %v", err))
	}
	return &UpdateUserRoleOutput{Body: UserResponse{
		ID:             uuid.UUID(u.ID.Bytes).String(),
		GitHubUsername: u.GitHubUsername,
		Role:           u.Role,
	}}, nil
}

func (h *Handler) GetSystemStatus(ctx context.Context, _ *struct{}) (*SystemStatusOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	out := &SystemStatusOutput{}
	out.Body.Enrichment = EnrichmentStatus{
		Enabled:   h.cfg.EnrichmentEnabled,
		Workers:   h.cfg.EnrichmentWorkers,
		QueueSize: h.cfg.EnrichmentQueueSize,
	}
	out.Body.Scanner = ScannerStatus{
		Enabled: h.cfg.ScannerEnabled,
	}
	out.Body.NATS = NATSStatus{
		Enabled: h.cfg.NATSEnabled,
		URL:     h.cfg.NATSURL,
	}
	return out, nil
}
