package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/pfenerty/ocidex/internal/service"
)

const (
	sessionCookieName = "ocidex_session"
	stateCookieName   = "ocidex_oauth_state"
	stateMaxAge       = 5 * time.Minute

	roleAdmin  = "admin"
	roleMember = "member"

	// descAdminOnly is the OpenAPI Description for operations whose only
	// authorization rule is RequireAdmin.
	descAdminOnly = "Admin-only."

	// descSelfScoped is the OpenAPI Description for the /users/me/*
	// collections. It states the one thing a caller could get wrong: these
	// select on ownership, not visibility, so public resources owned by
	// somebody else are absent even though the sibling list endpoint shows
	// them.
	descSelfScoped = "Scoped to the calling user: only resources you own, " +
		"excluding public resources owned by others."
)

// deriveFrontendURL returns a frontend URL using the request's host with the
// port from the configured FRONTEND_URL. This lets the post-OAuth redirect
// follow the host the browser used (e.g. Tailscale IP or localhost).
func deriveFrontendURL(r *http.Request, configuredFrontendURL string) string {
	parsed, err := url.Parse(configuredFrontendURL)
	if err != nil {
		return configuredFrontendURL
	}
	scheme := schemeHTTP
	if r.TLS != nil {
		scheme = schemeHTTPS
	}
	// r.Host may include a port (the API port); strip it to get just the hostname.
	host := r.Host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}
	port := parsed.Port()
	if port != "" {
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

// HandleLogin initiates GitHub OAuth flow.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)

	frontendURL := deriveFrontendURL(r, h.cfg.FrontendURL)
	state, err := h.stateCookie.Encode("oauth-state", map[string]string{
		"nonce":        nonceStr,
		"frontend_url": frontendURL,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is env-conditional; dev runs over http.
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int(stateMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.Environment == envProduction,
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

	// Clear the state cookie immediately. The attributes must mirror the ones
	// used when setting it — a clear sent with a stricter Secure than the
	// original would be rejected by the browser over http and never take effect.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is env-conditional; dev runs over http.
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.Environment == envProduction,
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

	secure := h.cfg.Environment == envProduction
	sameSite := http.SameSiteNoneMode
	if !secure {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is env-conditional; dev runs over http.
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   h.cfg.SessionMaxAgeDays * 86400,
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})

	frontendURL := stateData["frontend_url"]
	if frontendURL == "" {
		frontendURL = h.cfg.FrontendURL
	}
	http.Redirect(w, r, frontendURL, http.StatusSeeOther)
}

// HandleLogout clears the session.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil {
		_ = h.authService.DeleteSession(r.Context(), c.Value)
	}
	// Attributes mirror HandleCallback's setter so the clear is accepted in
	// both dev (http) and production (https).
	secure := h.cfg.Environment == envProduction
	sameSite := http.SameSiteNoneMode
	if !secure {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is env-conditional; dev runs over http.
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})
	w.WriteHeader(http.StatusNoContent)
}

// registerAuthOps registers raw chi routes and huma-managed auth endpoints.
func registerAuthOps(r chi.Router, api huma.API, h *Handler) {
	// Browser-redirect flows (not huma-managed).
	r.Get("/auth/login", h.HandleLogin)
	r.Get("/auth/callback", h.HandleCallback)
	r.Post("/auth/logout", h.HandleLogout)

	authMW := RequireAuthenticated(api)
	memberMW := RequireMember(api)
	adminMW := RequireAdmin(api)
	writeMW := RequireWrite(api)

	// Huma-managed endpoints.
	huma.Register(api, huma.Operation{
		OperationID: "get-me",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me",
		Summary:     "Get current user",
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetMe)

	// Self-scoped collections (ocidex-998g.2). Each one mirrors an existing
	// list endpoint but selects on ownership rather than visibility, so a
	// workspace UI does not have to fetch the whole catalogue and filter it
	// client-side. All are authenticated-class: there is nothing to authorize
	// beyond "who is asking", because the answer is defined by the asker.
	huma.Register(api, huma.Operation{
		OperationID: "list-my-namespaces",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me/namespaces",
		Summary:     "List my namespaces",
		Description: descSelfScoped,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListMyNamespaces)

	huma.Register(api, huma.Operation{
		OperationID: "list-my-sources",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me/sources",
		Summary:     "List my sources",
		Description: descSelfScoped,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListMySources)

	huma.Register(api, huma.Operation{
		OperationID: "list-my-registries",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me/registries",
		Summary:     "List my registries",
		Description: descSelfScoped,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListMyRegistries)

	huma.Register(api, huma.Operation{
		OperationID: "list-my-artifacts",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me/artifacts",
		Summary:     "List my artifacts",
		Description: descSelfScoped,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListMyArtifacts)

	huma.Register(api, huma.Operation{
		OperationID: "list-my-activity",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me/activity",
		Summary:     "List my recent activity",
		Description: "Every SBOM ingested into a namespace you own, newest first. " + descSelfScoped,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListMyActivity)

	huma.Register(api, huma.Operation{
		OperationID:   "create-api-key",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/keys",
		Summary:       "Create API key",
		Tags:          []string{tagAuth},
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{memberMW, writeMW},
	}, h.CreateAPIKey)

	huma.Register(api, huma.Operation{
		OperationID: "list-api-keys",
		Method:      http.MethodGet,
		Path:        "/api/v1/auth/keys",
		Summary:     "List API keys",
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{memberMW},
	}, h.ListAPIKeys)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-api-key",
		Method:        http.MethodDelete,
		Path:          "/api/v1/auth/keys/{id}",
		Summary:       "Delete API key",
		Tags:          []string{tagAuth},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{memberMW, writeMW},
	}, h.DeleteAPIKey)

	huma.Register(api, huma.Operation{
		OperationID: "list-users",
		Method:      http.MethodGet,
		Path:        "/api/v1/users",
		Summary:     "List users",
		Description: descAdminOnly,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{adminMW},
	}, h.ListUsers)

	huma.Register(api, huma.Operation{
		OperationID: "update-user-role",
		Method:      http.MethodPatch,
		Path:        "/api/v1/users/{id}/role",
		Summary:     "Update user role",
		Description: descAdminOnly,
		Tags:        []string{tagAuth},
		Middlewares: huma.Middlewares{adminMW, writeMW},
	}, h.UpdateUserRole)

	huma.Register(api, huma.Operation{
		OperationID: "get-system-status",
		Method:      http.MethodGet,
		Path:        "/api/v1/admin/status",
		Summary:     "Get system status",
		Description: descAdminOnly,
		Tags:        []string{tagAdmin},
		Middlewares: huma.Middlewares{adminMW},
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

// ListMyActivity returns the SBOMs ingested into the caller's namespaces,
// newest first. Unlike the other me-scoped collections this has no sibling to
// share a body with — there is no installation-wide activity feed — so it goes
// straight to the ownership-keyed service call (ocidex-998g.2).
func (h *Handler) ListMyActivity(ctx context.Context, in *ListMyActivityInput) (*ListMyActivityOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	cur, hasCursor, err := decodeTimeIDCursor(in.Cursor)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	result, err := h.searchService.ListOwnedActivity(ctx, user.ID, service.ActivityPage{
		Limit:           in.Limit,
		HasCursor:       hasCursor,
		CursorCreatedAt: cur.CreatedAt,
		CursorID:        cur.ID,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListMyActivityOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, in.Limit, func(a service.ActivityEntry) string {
		return encodeTimeIDCursor(a.CreatedAt, a.SBOMID)
	})
	return out, nil
}

func (h *Handler) CreateAPIKey(ctx context.Context, in *CreateAPIKeyInput) (*CreateAPIKeyOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	scope := in.Body.Scope
	if scope == "" {
		scope = scopeReadWrite
	}
	plaintext, err := h.authService.CreateAPIKey(ctx, user.ID, in.Body.Name, scope)
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
	keys, err := h.authService.ListAPIKeys(ctx, user.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing keys: %v", err))
	}
	out := &ListAPIKeysOutput{}
	out.Body.Keys = make([]KeyMetaResponse, len(keys))
	for i, k := range keys {
		out.Body.Keys[i] = KeyMetaResponse{
			ID:         uuid.UUID(k.ID.Bytes).String(),
			Name:       k.Name,
			Prefix:     k.Prefix,
			Scope:      k.Scope,
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
	out := &SystemStatusOutput{}
	out.Body.Enrichment = EnrichmentStatus{
		Enabled:   h.cfg.EnrichmentEnabled,
		Workers:   h.cfg.EnrichmentWorkers,
		QueueSize: h.cfg.EnrichmentQueueSize,
	}
	out.Body.Scanner = ScannerStatus{
		Enabled:       h.cfg.ScannerEnabled,
		PollerEnabled: h.cfg.RegistryPollerEnabled,
	}
	out.Body.NATS = NATSStatus{
		Enabled: true,
		URL:     h.cfg.NATSURL,
	}

	pingStart := time.Now()
	pingErr := h.db.Ping(ctx)
	out.Body.DB = DBStatus{
		OK:        pingErr == nil,
		LatencyMs: time.Since(pingStart).Milliseconds(),
	}

	if h.jobService != nil {
		queued, running, succ24h, fail24h, _ := h.jobService.CountByState(ctx)
		out.Body.ScanJobs = ScanJobsStatus{
			Queued:       queued,
			Running:      running,
			Succeeded24h: succ24h,
			Failed24h:    fail24h,
		}
	}

	return out, nil
}
