package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
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

// ListRegistries returns registries visible to the current user.
func (h *Handler) ListRegistries(ctx context.Context, input *ListRegistriesInput) (*ListRegistriesOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	filter := service.VisibilityFilter{
		IsAdmin: user.Role == roleAdmin,
		UserID:  user.ID,
	}
	result, err := h.registryService.ListPaged(ctx, filter, input.Limit, input.Offset)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing registries: %v", err))
	}
	users, err := h.authService.ListUsers(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing users: %v", err))
	}
	ownerNames := make(map[string]string, len(users))
	for _, u := range users {
		ownerNames[uuidToStr(u.ID)] = u.GitHubUsername
	}
	out := &ListRegistriesOutput{}
	out.Body.Data = make([]RegistryResponse, len(result.Data))
	for i, r := range result.Data {
		var ownerUsername *string
		if r.OwnerID != nil {
			if name, ok := ownerNames[*r.OwnerID]; ok {
				ownerUsername = &name
			}
		}
		out.Body.Data[i] = toRegistryResponse(r, h.cfg.APIBaseURL, ownerUsername)
	}
	out.Body.Pagination = paginationMeta(result)
	return out, nil
}

// GetRegistry returns a single registry by ID.
func (h *Handler) GetRegistry(ctx context.Context, in *GetRegistryInput) (*GetRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if !canManageRegistry(user, reg) && reg.Visibility == "private" {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &GetRegistryOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL, nil)}, nil
}

// CreateRegistry creates a new registry. Any authenticated user can create.
// For webhook-capable registries, a secret is auto-generated if not provided and returned once in the response.
func (h *Handler) CreateRegistry(ctx context.Context, in *CreateRegistryInput) (*CreateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if !isWriteAllowed(user) {
		return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
	}
	regType := in.Body.Type
	regURL := in.Body.URL
	if fixedURL, ok := typeFixedURL[regType]; ok {
		regURL = fixedURL
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

	// Auto-generate a webhook secret for webhook-capable registries when not provided.
	webhookSecret := in.Body.WebhookSecret
	var generatedSecret string
	if (scanMode == scanModeWebhook || scanMode == scanModeBoth) && (webhookSecret == nil || *webhookSecret == "") {
		s, err := generateWebhookSecret()
		if err != nil {
			return nil, huma.Error500InternalServerError("generating webhook secret")
		}
		generatedSecret = s
		webhookSecret = &generatedSecret
	}

	reg, err := h.registryService.Create(ctx, in.Body.Name, regType, regURL, in.Body.Insecure, webhookSecret, in.Body.Repositories, in.Body.RepositoryPatterns, in.Body.TagPatterns, scanMode, pollInterval, in.Body.AuthUsername, in.Body.AuthToken, user.ID, visibility, in.Body.IncludeUntagged)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("creating registry: %v", err))
	}
	return &CreateRegistryOutput{Body: CreateRegistryResponseBody{
		RegistryResponse: toRegistryResponse(reg, h.cfg.APIBaseURL, nil),
		WebhookSecret:    generatedSecret,
	}}, nil
}

// RegenerateWebhookSecret generates a new webhook secret for a registry (owner or admin).
// The previous secret is immediately invalidated.
func (h *Handler) RegenerateWebhookSecret(ctx context.Context, in *RegenerateWebhookSecretInput) (*RegenerateWebhookSecretOutput, error) {
	if user, ok := UserFromContext(ctx); ok && !isWriteAllowed(user) {
		return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
	}
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, huma.Error500InternalServerError("generating webhook secret")
	}
	_, err = h.registryService.Update(ctx, in.ID, existing.Name, existing.Type, existing.URL, existing.Insecure, &secret, existing.Enabled, existing.Repositories, existing.RepositoryPatterns, existing.TagPatterns, existing.ScanMode, existing.PollIntervalMinutes, existing.AuthUsername, existing.AuthToken, existing.Visibility, existing.IncludeUntagged)
	if err != nil {
		return nil, huma.Error500InternalServerError("updating webhook secret")
	}
	out := &RegenerateWebhookSecretOutput{}
	out.Body.WebhookSecret = secret
	return out, nil
}

// UpdateRegistry updates a registry (owner or admin).
func (h *Handler) UpdateRegistry(ctx context.Context, in *UpdateRegistryInput) (*UpdateRegistryOutput, error) {
	if user, ok := UserFromContext(ctx); ok && !isWriteAllowed(user) {
		return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
	}
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	regType := in.Body.Type
	regURL := in.Body.URL
	if fixedURL, ok := typeFixedURL[regType]; ok {
		regURL = fixedURL
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
	var reg service.Registry
	reg, err = h.registryService.Update(ctx, in.ID, in.Body.Name, regType, regURL, in.Body.Insecure, existing.WebhookSecret, in.Body.Enabled, in.Body.Repositories, in.Body.RepositoryPatterns, in.Body.TagPatterns, scanMode, pollInterval, in.Body.AuthUsername, in.Body.AuthToken, visibility, in.Body.IncludeUntagged)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &UpdateRegistryOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL, nil)}, nil
}

// DeleteRegistry deletes a registry (owner or admin).
func (h *Handler) DeleteRegistry(ctx context.Context, in *DeleteRegistryInput) (*struct{}, error) {
	if user, ok := UserFromContext(ctx); ok && !isWriteAllowed(user) {
		return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
	}
	if err := h.registryService.Delete(ctx, in.ID); err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return nil, nil
}

// TestRegistryConnection probes the registry's /v2/ endpoint.
func (h *Handler) TestRegistryConnection(ctx context.Context, in *TestRegistryConnectionInput) (*TestRegistryConnectionOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
	}
	if !isWriteAllowed(user) {
		return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
	}

	scheme := "https"
	if in.Body.Insecure {
		scheme = "http"
	}
	target := fmt.Sprintf("%s://%s/v2/", scheme, in.Body.URL)

	c := &http.Client{Timeout: 5 * time.Second}
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

// ScanRegistry triggers an ad-hoc catalog walk of a registry (owner or admin).
func (h *Handler) ScanRegistry(ctx context.Context, in *ScanRegistryInput) (*ScanRegistryOutput, error) {
	if user, ok := UserFromContext(ctx); ok && !isWriteAllowed(user) {
		return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if h.scanSubmitter == nil {
		return nil, huma.Error503ServiceUnavailable("scanner not enabled")
	}
	go func() { //nolint:gosec
		walkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		known := scanner.FetchKnownDigests(walkCtx, h.sbomService, reg.ID)
		queued, err := scanner.WalkRegistry(walkCtx, reg, h.scanSubmitter, known, slog.Default())
		if err != nil {
			slog.Error("ad-hoc registry scan failed", "registry", reg.Name, "err", err)
			return
		}
		slog.Info("ad-hoc registry scan complete", "registry", reg.Name, "queued", queued)
	}()
	out := &ScanRegistryOutput{}
	out.Body.Message = fmt.Sprintf("scan started for registry %q", reg.Name)
	return out, nil
}

// canManageRegistry returns true if the user is an admin or the registry owner.
func canManageRegistry(user service.AuthUser, reg service.Registry) bool {
	if user.Role == roleAdmin {
		return true
	}
	if reg.OwnerID != nil && user.ID.Valid {
		return *reg.OwnerID == uuidToStr(user.ID)
	}
	return false
}

func uuidToStr(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func toRegistryResponse(r service.Registry, apiBaseURL string, ownerUsername *string) RegistryResponse {
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
		OwnerID:             r.OwnerID,
		OwnerUsername:       ownerUsername,
		IncludeUntagged:     r.IncludeUntagged,
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
