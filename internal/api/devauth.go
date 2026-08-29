package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
)

// The dev-only persona switcher.
//
// The rig authenticates by API key today, which internal/api/middleware.go
// accepts as equivalent to a session cookie. That path never touches
// CreateSession or ValidateSession, so the browser rig exercises a code path
// production browsers never take, and the cookie half of the auth system —
// expiry, revocation on logout, the Secure/SameSite attributes — has no
// browser-level coverage at all.
//
// This endpoint closes that gap: it mints a *real* session for a seeded
// persona through the ordinary service call and returns the ordinary cookie.
// Everything downstream of the Set-Cookie is production's path unmodified.
//
// It is registered only when ENVIRONMENT is development, and the huma.Register
// call itself sits behind that check rather than the handler returning 403 —
// so the operation is absent from the production OpenAPI spec, absent from the
// router's route table, and absent from docs/AUTH_MATRIX.md. There is nothing
// to reach in a production build.

// DevSessionInput names the persona to become. The username is the one seeded
// by scripts/dev-auth.sh (devadmin, devowner, devsecurity, devviewer,
// devoutsider).
type DevSessionInput struct {
	Body struct {
		Username string `json:"username" minLength:"1" doc:"Seeded persona's username, e.g. devviewer"`
	}
}

// DevSessionOutput carries the session cookie plus enough of the persona for a
// switcher UI to render who it just became without a second round trip.
type DevSessionOutput struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
}

// DevMintSession issues a session cookie for a seeded persona.
//
// Lookup goes through ListUsers rather than a dedicated by-username query: the
// roster is five rows in the only environment this runs in, and adding SQL to
// the shipped repository layer for a development affordance would put the
// affordance in the production binary after all.
func (h *Handler) DevMintSession(ctx context.Context, in *DevSessionInput) (*DevSessionOutput, error) {
	users, err := h.authService.ListUsers(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("listing users")
	}

	var user service.AuthUser
	found := false
	for _, u := range users {
		if strings.EqualFold(u.GitHubUsername, in.Body.Username) {
			user, found = u, true
			break
		}
	}
	if !found {
		return nil, huma.Error404NotFound("no seeded user named " + in.Body.Username)
	}

	token, err := h.authService.CreateSession(ctx, user.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("creating session")
	}

	// Attributes mirror HandleCallback's non-production branch exactly. They
	// have to: a cookie set here that HandleLogout cannot clear would strand
	// the rig in a persona with no way out.
	out := &DevSessionOutput{
		SetCookie: http.Cookie{ //nolint:gosec // G124: dev-only, and the rig runs over http, so Secure would make the cookie unusable.
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   h.cfg.SessionMaxAgeDays * 86400,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   false,
		},
	}
	out.Body.Username = user.GitHubUsername
	out.Body.Role = user.Role
	return out, nil
}

// registerDevOps registers the development-only operations, and registers
// nothing at all outside development. A nil cfg (cmd/specgen, cmd/authmatrix
// and the conformance suite all build the router that way) counts as not
// development, which is what makes the generated spec and matrix production
// artifacts by construction.
func registerDevOps(api huma.API, h *Handler) {
	if h.cfg == nil || h.cfg.Environment != envDevelopment {
		return
	}
	// ENVIRONMENT defaults to development (internal/config/config.go), so an
	// operator who never set it gets this endpoint. Say so loudly at startup
	// rather than leaving it to be discovered in the route table.
	slog.Warn("registering development-only session mint endpoint",
		"operation", "dev-mint-session",
		"path", devSessionPath,
		"reason", "ENVIRONMENT="+h.cfg.Environment)

	huma.Register(api, huma.Operation{
		OperationID: "dev-mint-session",
		Method:      http.MethodPost,
		Path:        devSessionPath,
		Summary:     "Mint a session for a seeded dev persona",
		Description: "Development builds only. Issues a real session cookie for one of the personas seeded by scripts/dev-auth.sh.",
		Tags:        []string{tagAuth},
	}, h.DevMintSession)
}
