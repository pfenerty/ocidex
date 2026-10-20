package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/trust"
)

const (
	scanModeWebhook = "webhook"
	scanModePoll    = "poll"
	scanModeBoth    = "both"
)

// typeFixedURL maps registry types that always use a canonical URL.
// If a type is present here, the submitted URL is ignored and replaced.
var typeFixedURL = map[string]string{
	"docker": "registry-1.docker.io",
	"ghcr":   "ghcr.io",
}

// typeSupportsWebhook indicates whether a registry type can receive inbound
// push notifications from the registry. Types that don't support webhooks
// must use poll mode, which requires REGISTRY_POLLER_ENABLED=true.
var typeSupportsWebhook = map[string]bool{
	"docker":  false,
	"ghcr":    false,
	"zot":     true,
	"harbor":  true,
	"generic": true,
}

// resolveRegistryType validates that scanMode is compatible with regType and returns
// the effective scan mode (defaulting to poll for types that don't support webhooks).
// Returns an error if the combination is invalid or if polling is required but disabled.
func (h *Handler) resolveRegistryType(regType, scanMode string) (string, error) {
	if !typeSupportsWebhook[regType] {
		if scanMode == scanModeWebhook || scanMode == scanModeBoth {
			return "", huma.Error422UnprocessableEntity(fmt.Sprintf("registry type %q does not support webhook scan mode; use 'poll'", regType))
		}
		if !h.cfg.RegistryPollerEnabled {
			return "", huma.Error422UnprocessableEntity(fmt.Sprintf("registry type %q requires polling, but REGISTRY_POLLER_ENABLED is not set", regType))
		}
		if scanMode == "" {
			scanMode = scanModePoll
		}
	}
	if (scanMode == scanModePoll || scanMode == scanModeBoth) && !h.cfg.RegistryPollerEnabled {
		return "", huma.Error422UnprocessableEntity("scan_mode 'poll' and 'both' require REGISTRY_POLLER_ENABLED=true")
	}
	return scanMode, nil
}

// generateWebhookSecret returns a cryptographically random 32-byte hex-encoded secret.
func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureWebhookSecret returns the provided webhook secret, or auto-generates one for
// webhook-capable scan modes when none was supplied. Returns the (possibly generated)
// secret and, separately, the generated value alone (empty if none was generated) so
// callers can decide whether to reveal it in a response.
func ensureWebhookSecret(scanMode string, provided *string) (secret *string, generated string, err error) {
	if (scanMode != scanModeWebhook && scanMode != scanModeBoth) || (provided != nil && *provided != "") {
		return provided, "", nil
	}
	s, err := generateWebhookSecret()
	if err != nil {
		return nil, "", huma.Error500InternalServerError("generating webhook secret")
	}
	return &s, s, nil
}

// validateVerificationConfig rejects a keyless verification_mode that's missing the
// trust_identity/trust_issuer it needs to match a Fulcio certificate against, and a
// public_key verification_mode that's missing trust_public_key.
// validateRegistryURL checks the shape of a user-supplied registry address
// (ocidex-avsz.8): an optional http/https scheme (http only with insecure), a
// host with an optional numeric port, and nothing else — credentials belong in
// auth_username/auth_token, and a path, query or fragment would be silently
// dropped or mangled by the scanner. A literal IP the egress policy refuses is
// rejected here so the user hears about it now rather than from a failed scan;
// the dial-time guard in internal/netguard remains the real enforcement, since a
// hostname can resolve anywhere.
func validateRegistryURL(raw string, insecure bool, egress netguard.Policy) error {
	invalid := func(msg string) error {
		return huma.Error422UnprocessableEntity("invalid registry url", &huma.ErrorDetail{
			Location: "body.url", Message: msg, Value: raw,
		})
	}
	rest, msg := stripRegistryScheme(raw, insecure)
	if msg != "" {
		return invalid(msg)
	}
	u, err := url.Parse("//" + rest)
	if err != nil {
		return invalid(fmt.Sprintf("not a valid host[:port]: %v", err))
	}
	switch {
	case u.User != nil:
		return invalid("must not contain credentials; use auth_username and auth_token")
	case u.RawQuery != "" || u.ForceQuery:
		return invalid("must not contain a query")
	case u.Fragment != "" || strings.Contains(rest, "#"):
		return invalid("must not contain a fragment")
	case u.Path != "" && u.Path != "/":
		return invalid("must not contain a path; list repositories in repositories instead")
	case u.Hostname() == "":
		return invalid("host is required")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		if err := egress.Check(ip); err != nil {
			return invalid(fmt.Sprintf("%s is refused by this installation's egress policy", ip))
		}
	}
	return nil
}

// stripRegistryScheme returns raw without its scheme, or a message saying why
// the scheme is not acceptable.
func stripRegistryScheme(raw string, insecure bool) (rest, msg string) {
	scheme, after, ok := strings.Cut(raw, "://")
	if !ok {
		return raw, ""
	}
	switch strings.ToLower(scheme) {
	case schemeHTTPS:
		return after, ""
	case schemeHTTP:
		if !insecure {
			return "", "http:// requires insecure to be true"
		}
		return after, ""
	default:
		return "", "scheme must be http or https"
	}
}

func validateVerificationConfig(verificationMode string, trustPublicKey, trustIdentity, trustIssuer *string) error {
	switch verificationMode {
	case trust.ModeKeyless:
		if trustIdentity == nil || *trustIdentity == "" || trustIssuer == nil || *trustIssuer == "" {
			return huma.Error400BadRequest("trust_identity and trust_issuer are required when verification_mode is keyless")
		}
	case trust.ModePublicKey:
		if trustPublicKey == nil || *trustPublicKey == "" {
			return huma.Error400BadRequest("trust_public_key is required when verification_mode is public_key")
		}
	}
	return nil
}

// ListRegistries returns registries visible to the current user.
func (h *Handler) ListRegistries(ctx context.Context, input *ListRegistriesInput) (*ListRegistriesOutput, error) {
	return h.listRegistries(ctx, visibilityFilterFromContext(ctx), input.Limit, input.Offset)
}

// ListMyRegistries returns only the registries in namespaces the caller owns.
// Offset pagination, matching /registries: the ordering column is immutable but
// the page is one the UI numbers, so ADR-043 rule 3 sends it to offset.
func (h *Handler) ListMyRegistries(ctx context.Context, input *ListMyRegistriesInput) (*ListRegistriesOutput, error) {
	return h.listRegistries(ctx, ownedFilterFromContext(ctx), input.Limit, input.Offset)
}

func (h *Handler) listRegistries(ctx context.Context, vis service.VisibilityFilter, limit, offset int32) (*ListRegistriesOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	result, err := h.registryService.ListPaged(ctx, vis, limit, offset)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing registries: %v", err))
	}
	out := &ListRegistriesOutput{}
	out.Body.Data = make([]RegistryResponse, len(result.Data))
	for i, r := range result.Data {
		out.Body.Data[i] = toRegistryResponse(r, h.cfg.APIBaseURL)
	}
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// GetRegistryTrustSummary returns per-registry artifact counts across all five
// signing statuses, restricted to the namespaces the caller can see. An admin
// gets the cross-tenant view; a namespace owner gets their own signing posture.
func (h *Handler) GetRegistryTrustSummary(ctx context.Context, _ *struct{}) (*GetRegistryTrustSummaryOutput, error) {
	rows, err := h.registryService.TrustSummary(ctx, visibilityFilterFromContext(ctx))
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing registry trust summary: %v", err))
	}
	out := &GetRegistryTrustSummaryOutput{}
	out.Body.Data = rows
	return out, nil
}

// ListRecentDrift returns the most recent provenance drift events visible to
// the caller, scoped the same way as GetRegistryTrustSummary.
func (h *Handler) ListRecentDrift(ctx context.Context, in *ListRecentDriftInput) (*ListRecentDriftOutput, error) {
	return h.listRecentDrift(ctx, in.CursorParams, visibilityFilterFromContext(ctx))
}

// ListMyDriftFeed is ListRecentDrift narrowed to namespaces the caller owns
// (ocidex-998g.5). The dashboard panel is titled "drift on my artifacts", and
// the default visibility filter would quietly include everyone else's public
// ones, so the panel would be lying about whose problem it is showing.
func (h *Handler) ListMyDriftFeed(ctx context.Context, in *ListMyDriftFeedInput) (*ListRecentDriftOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	return h.listRecentDrift(ctx, in.CursorParams, ownedFilterFromContext(ctx))
}

func (h *Handler) listRecentDrift(ctx context.Context, in CursorParams, vis service.VisibilityFilter) (*ListRecentDriftOutput, error) {
	cur, hasCursor, err := decodeTimeIDCursor(in.Cursor)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	result, err := h.searchService.ListRecentProvenanceDrift(ctx, service.DriftPage{
		Limit:            in.Limit,
		HasCursor:        hasCursor,
		CursorDetectedAt: cur.CreatedAt,
		CursorID:         cur.ID,
	}, vis)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing recent provenance drift: %v", err))
	}
	out := &ListRecentDriftOutput{}
	out.Body.Data = result.Data
	out.Body.Pagination = cursorMeta(result.Data, result.HasMore, in.Limit,
		func(d service.RecentDriftEntry) string { return encodeTimeIDCursor(d.DetectedAt, d.ID) })
	return out, nil
}

// GetRegistry returns a single registry by ID.
func (h *Handler) GetRegistry(ctx context.Context, in *GetRegistryInput) (*GetRegistryOutput, error) {
	_, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if reg.Visibility == visibilityPrivate &&
		!canFromContext(ctx, reg.NamespaceID, authz.CapReadPrivate) {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &GetRegistryOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL)}, nil
}

// GetRegistryByName returns a single registry by name.
func (h *Handler) GetRegistryByName(ctx context.Context, in *GetRegistryByNameInput) (*GetRegistryByNameOutput, error) {
	_, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	reg, err := h.registryService.GetByName(ctx, in.Name)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if reg.Visibility == visibilityPrivate &&
		!canFromContext(ctx, reg.NamespaceID, authz.CapReadPrivate) {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &GetRegistryByNameOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL)}, nil
}

// CreateRegistry creates a new registry. Any authenticated user can create.
// For webhook-capable registries, a secret is auto-generated if not provided and returned once in the response.
func (h *Handler) CreateRegistry(ctx context.Context, in *CreateRegistryInput) (*CreateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	regType := in.Body.Type
	regURL := in.Body.URL
	if fixedURL, ok := typeFixedURL[regType]; ok {
		regURL = fixedURL
	} else if err := validateRegistryURL(regURL, in.Body.Insecure, h.egress()); err != nil {
		return nil, err
	}

	scanMode := in.Body.ScanMode
	var err error
	scanMode, err = h.resolveRegistryType(regType, scanMode)
	if err != nil {
		return nil, err
	}
	if scanMode == "" {
		scanMode = scanModeWebhook
	}
	pollInterval := in.Body.PollIntervalMinutes
	if pollInterval == 0 {
		pollInterval = 60
	}
	visibility := in.Body.Visibility
	if visibility == "" {
		visibility = "public"
	}

	webhookSecret, generatedSecret, err := ensureWebhookSecret(scanMode, in.Body.WebhookSecret)
	if err != nil {
		return nil, err
	}

	verificationMode := in.Body.VerificationMode
	if verificationMode == "" {
		verificationMode = trust.ModeNone
	}
	if err := validateVerificationConfig(verificationMode, in.Body.TrustPublicKey, in.Body.TrustIdentity, in.Body.TrustIssuer); err != nil {
		return nil, err
	}
	reg, err := h.createRegistry(ctx, user, service.CreateRegistryParams{
		Name:                in.Body.Name,
		Namespace:           in.Body.Namespace,
		Type:                regType,
		URL:                 regURL,
		Insecure:            in.Body.Insecure,
		WebhookSecret:       webhookSecret,
		Repositories:        in.Body.Repositories,
		RepositoryPatterns:  in.Body.RepositoryPatterns,
		TagPatterns:         in.Body.TagPatterns,
		ScanMode:            scanMode,
		PollIntervalMinutes: pollInterval,
		AuthUsername:        in.Body.AuthUsername,
		AuthToken:           in.Body.AuthToken,
		CreatorID:           user.ID,
		Visibility:          visibility,
		IncludeUntagged:     in.Body.IncludeUntagged,
		VerificationMode:    verificationMode,
		TrustPublicKey:      in.Body.TrustPublicKey,
		TrustIdentity:       in.Body.TrustIdentity,
		TrustIssuer:         in.Body.TrustIssuer,
		ManagedBy:           in.Body.ManagedBy,
		ManagedRef:          in.Body.ManagedRef,
		TagLimit:            in.Body.TagLimit,
		TagOrder:            tagOrderFromAPI(in.Body.TagOrder),
		MaxTagAgeDays:       in.Body.MaxTagAgeDays,
	})
	if err != nil {
		return nil, err
	}
	return &CreateRegistryOutput{Body: CreateRegistryResponseBody{
		RegistryResponse: toRegistryResponse(reg, h.cfg.APIBaseURL),
		WebhookSecret:    generatedSecret,
	}}, nil
}

// createRegistry creates a registry, authorizing the caller against the
// namespace the request names when that namespace already exists
// (ocidex-avsz.2). Without this, naming another tenant's namespace planted a
// registry — URL, credentials, schedule and all — inside it.
//
// The service only ever creates a named namespace; one that exists comes back
// as ErrNamespaceExists. That includes the race where another request creates
// it between the lookup here and the insert there, which is why the check
// re-runs once on that sentinel rather than trusting the first lookup.
func (h *Handler) createRegistry(
	ctx context.Context, user service.AuthUser, params service.CreateRegistryParams,
) (service.Registry, error) {
	for attempt := 0; ; attempt++ {
		if params.Namespace != "" {
			id, err := h.authorizeExistingNamespace(ctx, user, params.Namespace, authz.CapManageSource)
			if err != nil {
				return service.Registry{}, err
			}
			params.NamespaceID = id
		}
		// Anything but an existing namespace means minting one.
		if params.NamespaceID == "" {
			if err := h.requireNamespaceCreation(user); err != nil {
				return service.Registry{}, err
			}
		}
		reg, err := h.registryService.Create(ctx, params)
		if errors.Is(err, service.ErrNamespaceExists) && attempt == 0 {
			continue
		}
		if err != nil {
			return service.Registry{}, mapServiceError(err)
		}
		return reg, nil
	}
}

// authorizeExistingNamespace looks up the namespace called name and, if it
// exists, requires c in it, returning its ID. A namespace that does not exist
// yields "" and no error: creating it makes the caller its owner.
//
// A caller with no membership gets 404 rather than 403, so the endpoint cannot
// be used to probe which names other tenants have taken.
func (h *Handler) authorizeExistingNamespace(
	ctx context.Context, user service.AuthUser, name string, c authz.Capability,
) (string, error) {
	ns, err := h.namespaceService.GetByName(ctx, name)
	if errors.Is(err, service.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", mapServiceError(err)
	}
	if _, member := user.Grants[ns.ID]; !member && user.Role != roleAdmin {
		return "", huma.Error404NotFound("namespace not found")
	}
	if !can(user, ns.ID, c) {
		return "", huma.Error403Forbidden("forbidden")
	}
	return ns.ID, nil
}

// RegenerateWebhookSecret generates a new webhook secret for a registry. The
// route requires read_secret on the registry's namespace (ADR-046).
// The previous secret is immediately invalidated.
func (h *Handler) RegenerateWebhookSecret(ctx context.Context, in *RegenerateWebhookSecretInput) (*RegenerateWebhookSecretOutput, error) {
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, huma.Error500InternalServerError("generating webhook secret")
	}
	_, err = h.registryService.Update(ctx, service.UpdateRegistryParams{
		ID:                  in.ID,
		Name:                existing.Name,
		Type:                existing.Type,
		URL:                 existing.URL,
		Insecure:            existing.Insecure,
		WebhookSecret:       &secret,
		Enabled:             existing.Enabled,
		Repositories:        existing.Repositories,
		RepositoryPatterns:  existing.RepositoryPatterns,
		TagPatterns:         existing.TagPatterns,
		ScanMode:            existing.ScanMode,
		PollIntervalMinutes: existing.PollIntervalMinutes,
		AuthUsername:        existing.AuthUsername,
		AuthToken:           existing.AuthToken,
		Visibility:          existing.Visibility,
		IncludeUntagged:     existing.IncludeUntagged,
		VerificationMode:    existing.VerificationMode,
		TrustPublicKey:      existing.TrustPublicKey,
		TrustIdentity:       existing.TrustIdentity,
		TrustIssuer:         existing.TrustIssuer,
		ManagedBy:           existing.ManagedBy,
		ManagedRef:          existing.ManagedRef,
		TagLimit:            &existing.TagLimit,
		TagOrder:            &existing.TagOrder,
		MaxTagAgeDays:       &existing.MaxTagAgeDays,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError("updating webhook secret")
	}
	out := &RegenerateWebhookSecretOutput{}
	out.Body.WebhookSecret = secret
	return out, nil
}

// UpdateRegistry updates a registry. The route requires manage_source on the
// registry's namespace (ADR-046).
func (h *Handler) UpdateRegistry(ctx context.Context, in *UpdateRegistryInput) (*UpdateRegistryOutput, error) {
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	regType := in.Body.Type
	regURL := in.Body.URL
	if fixedURL, ok := typeFixedURL[regType]; ok {
		regURL = fixedURL
	} else if err := validateRegistryURL(regURL, in.Body.Insecure, h.egress()); err != nil {
		return nil, err
	}

	scanMode := in.Body.ScanMode
	scanMode, err = h.resolveRegistryType(regType, scanMode)
	if err != nil {
		return nil, err
	}
	if scanMode == "" {
		scanMode = existing.ScanMode
	}
	pollInterval := in.Body.PollIntervalMinutes
	if pollInterval == 0 {
		pollInterval = existing.PollIntervalMinutes
	}
	visibility := in.Body.Visibility
	if visibility == "" {
		visibility = existing.Visibility
	}
	updateVerificationMode := in.Body.VerificationMode
	if updateVerificationMode == "" {
		updateVerificationMode = existing.VerificationMode
	}
	updateTrustPublicKey := in.Body.TrustPublicKey
	if updateTrustPublicKey == nil {
		updateTrustPublicKey = existing.TrustPublicKey
	}
	updateTrustIdentity := in.Body.TrustIdentity
	if updateTrustIdentity == nil {
		updateTrustIdentity = existing.TrustIdentity
	}
	updateTrustIssuer := in.Body.TrustIssuer
	if updateTrustIssuer == nil {
		updateTrustIssuer = existing.TrustIssuer
	}
	if err := validateVerificationConfig(updateVerificationMode, updateTrustPublicKey, updateTrustIdentity, updateTrustIssuer); err != nil {
		return nil, err
	}
	var reg service.Registry
	reg, err = h.registryService.Update(ctx, service.UpdateRegistryParams{
		ID:                  in.ID,
		Name:                in.Body.Name,
		Type:                regType,
		URL:                 regURL,
		Insecure:            in.Body.Insecure,
		WebhookSecret:       existing.WebhookSecret,
		Enabled:             in.Body.Enabled,
		Repositories:        in.Body.Repositories,
		RepositoryPatterns:  in.Body.RepositoryPatterns,
		TagPatterns:         in.Body.TagPatterns,
		ScanMode:            scanMode,
		PollIntervalMinutes: pollInterval,
		AuthUsername:        in.Body.AuthUsername,
		AuthToken:           in.Body.AuthToken,
		Visibility:          visibility,
		IncludeUntagged:     in.Body.IncludeUntagged,
		VerificationMode:    in.Body.VerificationMode,
		TrustPublicKey:      in.Body.TrustPublicKey,
		TrustIdentity:       in.Body.TrustIdentity,
		TrustIssuer:         in.Body.TrustIssuer,
		// nil leaves the existing marker alone, so a UI edit of an
		// operator-owned registry can't quietly claim it as unmanaged.
		ManagedBy:  in.Body.ManagedBy,
		ManagedRef: in.Body.ManagedRef,
		// nil keeps the stored window, so a client that predates ADR-0053
		// can't reset it to unlimited by leaving the fields out.
		TagLimit:      in.Body.TagLimit,
		TagOrder:      tagOrderPtrFromAPI(in.Body.TagOrder),
		MaxTagAgeDays: in.Body.MaxTagAgeDays,
	})
	var valErr *service.ValidationError
	if errors.As(err, &valErr) {
		return nil, mapServiceError(err)
	}
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &UpdateRegistryOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL)}, nil
}

// DeleteRegistry deletes a registry. The route requires manage_source on the
// registry's namespace (ADR-046).
func (h *Handler) DeleteRegistry(ctx context.Context, in *DeleteRegistryInput) (*struct{}, error) {
	if err := h.registryService.Delete(ctx, in.ID); err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return nil, nil
}

// PreviewRegistryConfig runs the ADR-0053 selection for a registry that is not
// saved yet, so a form can show what it would scan before it scans anything.
// It needs what create needs: an authenticated caller and a URL the egress
// policy admits.
func (h *Handler) PreviewRegistryConfig(ctx context.Context, in *PreviewRegistryConfigInput) (*RegistryPreviewOutput, error) {
	b := in.Body
	regURL := b.URL
	if fixedURL, ok := typeFixedURL[b.Type]; ok {
		regURL = fixedURL
	} else if err := validateRegistryURL(regURL, b.Insecure, h.egress()); err != nil {
		return nil, err
	}
	tagLimit := service.DefaultTagLimit
	if b.TagLimit != nil {
		tagLimit = *b.TagLimit
	}
	tagOrder := tagOrderFromAPI(b.TagOrder)
	if err := service.ValidateScanScope(tagLimit, tagOrder, b.MaxTagAgeDays, b.TagPatterns); err != nil {
		return nil, mapServiceError(err)
	}
	return h.previewRegistry(ctx, service.Registry{
		Type:               b.Type,
		URL:                regURL,
		Insecure:           b.Insecure,
		AuthUsername:       b.AuthUsername,
		AuthToken:          b.AuthToken,
		Repositories:       b.Repositories,
		RepositoryPatterns: b.RepositoryPatterns,
		TagPatterns:        b.TagPatterns,
		IncludeUntagged:    b.IncludeUntagged,
		TagLimit:           tagLimit,
		TagOrder:           tagOrder,
		MaxTagAgeDays:      b.MaxTagAgeDays,
	})
}

// GetRegistryPreview runs the selection for a saved registry, with its stored
// credentials. The route requires trigger_scan, as a scan does (ADR-046).
func (h *Handler) GetRegistryPreview(ctx context.Context, in *GetRegistryPreviewInput) (*RegistryPreviewOutput, error) {
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return h.previewRegistry(ctx, reg)
}

func (h *Handler) previewRegistry(ctx context.Context, reg service.Registry) (*RegistryPreviewOutput, error) {
	p, err := scanner.PreviewRegistry(ctx, reg, h.egress(), slog.Default())
	if err != nil {
		return nil, huma.Error502BadGateway(fmt.Sprintf("previewing registry: %v", err))
	}
	return &RegistryPreviewOutput{Body: p}, nil
}

// egress is the policy every dial to a user-supplied registry obeys. A handler
// built without config (tests) gets the default, which is the strict one.
func (h *Handler) egress() netguard.Policy {
	if h.cfg == nil {
		return netguard.Policy{}
	}
	return h.cfg.EgressPolicy
}

// TestRegistryConnection probes the registry's /v2/ endpoint.
func (h *Handler) TestRegistryConnection(ctx context.Context, in *TestRegistryConnectionInput) (*TestRegistryConnectionOutput, error) {
	scheme := schemeHTTPS
	if in.Body.Insecure {
		scheme = schemeHTTP
	}
	target := fmt.Sprintf("%s://%s/v2/", scheme, in.Body.URL)

	c := &http.Client{Timeout: 5 * time.Second, Transport: h.egress().Transport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		out := &TestRegistryConnectionOutput{}
		out.Body.Reachable = false
		out.Body.Message = fmt.Sprintf("invalid URL: %v", err)
		return out, nil
	}
	if in.Body.AuthToken != nil && *in.Body.AuthToken != "" {
		username := "ocidex"
		if in.Body.AuthUsername != nil && *in.Body.AuthUsername != "" {
			username = *in.Body.AuthUsername
		}
		req.SetBasicAuth(username, *in.Body.AuthToken)
	}

	resp, err := c.Do(req) //nolint:gosec
	out := &TestRegistryConnectionOutput{}
	if err != nil {
		out.Body.Reachable = false
		out.Body.Message = err.Error()
		return out, nil
	}
	defer resp.Body.Close()

	// 200 OK = open registry; 401 Unauthorized = auth required but registry is up.
	out.Body.Reachable = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
	out.Body.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	return out, nil
}

// ScanRegistry triggers an ad-hoc catalog walk of a registry. The route
// requires trigger_scan on the registry's namespace (ADR-046).
func (h *Handler) ScanRegistry(ctx context.Context, in *ScanRegistryInput) (*ScanRegistryOutput, error) {
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if h.scanSubmitter == nil {
		return nil, huma.Error503ServiceUnavailable("scanner not enabled")
	}
	force := in.Force
	go func() { //nolint:gosec
		walkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		// Skip already-scanned digests at the walk level (same as the scheduled
		// scanner) so a re-scan only re-pulls new/changed images. force=true passes
		// nil so every digest is re-walked and re-queued via the InsertScanJob upsert
		// — used to repopulate enrichment for already-ingested images.
		// force also re-queues digests whose SBOM was deleted on purpose
		// (pruned, ADR-0053 S6); a plain walk leaves those alone.
		var known map[string]bool
		sub := h.scanSubmitter
		if force {
			sub = scanner.ForceSubmitter{Submitter: sub}
		} else {
			known = scanner.FetchKnownDigests(walkCtx, h.sbomService, reg.ID)
		}
		stats, err := scanner.WalkRegistryStats(walkCtx, reg, sub, known, h.egress(), slog.Default())
		scanner.RecordWalk(walkCtx, h.registryService, reg, stats, slog.Default())
		queued := stats.Queued
		if err != nil {
			slog.Error("ad-hoc registry scan failed", "registry", reg.Name, "err", err)
			return
		}
		slog.Info("ad-hoc registry scan complete", "registry", reg.Name, "queued", queued, "force", force)
	}()
	out := &ScanRegistryOutput{}
	out.Body.Message = fmt.Sprintf("scan started for registry %q", reg.Name)
	return out, nil
}

func uuidToStr(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// tagOrderAuto is the API's name for the order the service stores as "".
const tagOrderAuto = "auto"

func tagOrderFromAPI(s string) string {
	if s == tagOrderAuto {
		return ""
	}
	return s
}

func tagOrderPtrFromAPI(s *string) *string {
	if s == nil {
		return nil
	}
	v := tagOrderFromAPI(*s)
	return &v
}

func toRegistryResponse(r service.Registry, apiBaseURL string) RegistryResponse {
	rr := RegistryResponse{
		ID:                  r.ID,
		Name:                r.Name,
		Type:                r.Type,
		URL:                 r.URL,
		Insecure:            r.Insecure,
		HasSecret:           r.WebhookSecret != nil && *r.WebhookSecret != "",
		HasAuth:             r.HasAuth(),
		Enabled:             r.Enabled,
		WebhookURL:          apiBaseURL + "/api/v1/registries/" + r.ID + "/webhook",
		Repositories:        r.Repositories,
		RepositoryPatterns:  r.RepositoryPatterns,
		TagPatterns:         r.TagPatterns,
		ScanMode:            r.ScanMode,
		PollIntervalMinutes: r.PollIntervalMinutes,
		CreatedAt:           r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:           r.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Visibility:          r.Visibility,
		IncludeUntagged:     r.IncludeUntagged,
		VerificationMode:    r.VerificationMode,
		TrustPublicKey:      r.TrustPublicKey,
		TrustIdentity:       r.TrustIdentity,
		TrustIssuer:         r.TrustIssuer,
		ManagedBy:           r.ManagedBy,
		ManagedRef:          r.ManagedRef,
		TagLimit:            r.TagLimit,
		TagOrder:            r.TagOrder,
		MaxTagAgeDays:       r.MaxTagAgeDays,
		LastWalk:            r.LastWalk,
	}
	if rr.TagOrder == "" {
		rr.TagOrder = tagOrderAuto
	}
	if r.LastPolledAt != nil {
		s := r.LastPolledAt.UTC().Format("2006-01-02T15:04:05Z")
		rr.LastPolledAt = &s
	}
	if rr.Repositories == nil {
		rr.Repositories = []string{}
	}
	if rr.RepositoryPatterns == nil {
		rr.RepositoryPatterns = []string{}
	}
	if rr.TagPatterns == nil {
		rr.TagPatterns = []string{}
	}
	return rr
}
