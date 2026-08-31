package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/pfenerty/ocidex/internal/auth"
	"github.com/pfenerty/ocidex/internal/service"
)

const (
	// oauthModeLink marks a round trip started from the account page rather
	// than the login page. It lives in the signed state cookie, so a caller
	// cannot flip a sign-in into a link or the other way round.
	oauthModeLink = "link"

	// accountPath is where the browser lands after a link round trip. The
	// outcome rides in ?link= because the trip ends in a redirect from the
	// issuer, not in a response to a request the page made.
	accountPath = "/admin/account"
)

// finishIdentityLink completes a round trip that began as a link.
//
// The account is taken from the live session and cross-checked against the one
// named in the state. Both are trustworthy on their own — the state cookie is
// signed and the session cookie is the session — but they can disagree if the
// person signed out and back in as somebody else mid-flight, and linking an
// identity onto the account they *were* using would be silent and wrong.
func (h *Handler) finishIdentityLink(
	w http.ResponseWriter, r *http.Request, provider, code string, stateData map[string]string,
) {
	frontendURL := stateData["frontend_url"]
	if frontendURL == "" {
		frontendURL = h.cfg.FrontendURL
	}

	sessionCookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	user, err := h.authService.ValidateSession(r.Context(), sessionCookie.Value)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if uuid.UUID(user.ID.Bytes).String() != stateData["user_id"] {
		http.Error(w, "session changed during linking", http.StatusBadRequest)
		return
	}

	outcome := "ok"
	if _, err := h.authService.LinkIdentity(r.Context(), user.ID, provider, code, stateData["verifier"]); err != nil {
		outcome = "error"
		if errors.Is(err, service.ErrConflict) {
			outcome = "conflict"
		}
	}

	// The destination is the configured frontend URL with a fixed path and a
	// fixed query; nothing from the request reaches it.
	http.Redirect(w, r, frontendURL+accountPath+"?link="+outcome, http.StatusSeeOther) //nolint:gosec // G710
}

// ListAuthProviders lists the issuers this deployment is configured with.
//
// It is public because the login page has to render it before anyone is signed
// in. It reveals only the names an administrator chose for their own issuers,
// which is what the sign-in buttons say anyway.
func (h *Handler) ListAuthProviders(_ context.Context, _ *struct{}) (*ListProvidersOutput, error) {
	names := h.authService.ProviderNames()
	out := &ListProvidersOutput{}
	out.Body.Providers = make([]ProviderResponse, len(names))
	for i, name := range names {
		out.Body.Providers[i] = ProviderResponse{
			Name:        name,
			DisplayName: providerDisplayName(name),
			LoginPath:   "/auth/login/" + name,
		}
	}

	return out, nil
}

// providerDisplayName is the label a sign-in button carries.
//
// "github" is the one issuer with a name of its own; everything else is
// "oidc:<name>", where <name> is what the operator called their issuer and is
// therefore already the most meaningful thing to show.
func providerDisplayName(name string) string {
	if name == auth.ProviderGitHub {
		return "GitHub"
	}
	return strings.TrimPrefix(name, auth.ProviderOIDCPrefix)
}

// ListMyIdentities returns the issuers the caller can sign in with.
func (h *Handler) ListMyIdentities(ctx context.Context, _ *struct{}) (*ListIdentitiesOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	rows, err := h.authService.ListIdentities(ctx, user.ID)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListIdentitiesOutput{}
	out.Body.Identities = make([]IdentityResponse, len(rows))
	for i, row := range rows {
		out.Body.Identities[i] = IdentityResponse{
			ID:          uuid.UUID(row.ID.Bytes).String(),
			Provider:    row.Provider,
			DisplayName: providerDisplayName(row.Provider),
			Subject:     row.Subject,
			Email:       row.Email,
			CreatedAt:   row.CreatedAt,
		}
	}

	return out, nil
}

// StartIdentityLink begins the round trip that links a second issuer.
//
// It answers with a URL for the page to navigate to rather than redirecting:
// the caller is a fetch from an already-loaded page, and a 3xx there would be
// followed by the browser into a cross-origin request the page cannot use. The
// state cookie it sets is what makes the eventual callback a link.
func (h *Handler) StartIdentityLink(ctx context.Context, in *StartIdentityLinkInput) (*StartIdentityLinkOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	r, ok := requestFromContext(ctx)
	if !ok {
		return nil, huma.Error500InternalServerError("no request in context")
	}

	authURL, state, err := h.beginOAuth(r, in.Body.Provider, map[string]string{
		"mode":    oauthModeLink,
		"user_id": uuid.UUID(user.ID.Bytes).String(),
	})
	if err != nil {
		return nil, huma.Error400BadRequest("unknown identity provider")
	}

	out := &StartIdentityLinkOutput{}
	out.SetCookie = *stateCookieFor(h.cfg.Environment, state, int(stateMaxAge.Seconds()))
	out.Body.AuthorizeURL = authURL

	return out, nil
}

// UnlinkIdentity removes one of the caller's identities.
func (h *Handler) UnlinkIdentity(ctx context.Context, in *UnlinkIdentityInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	identityID, err := parseUUID(in.ID)
	if err != nil {
		return nil, err
	}
	if err := h.authService.UnlinkIdentity(ctx, user.ID, identityID); err != nil {
		if errors.Is(err, service.ErrConflict) {
			return nil, huma.Error409Conflict("cannot unlink the only way to sign in to this account")
		}
		return nil, mapServiceError(err)
	}

	return nil, nil
}
