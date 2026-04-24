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

// generateWebhookSecret returns a cryptographically random 32-byte hex-encoded secret.
func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ListRegistries returns registries visible to the current user.
func (h *Handler) ListRegistries(ctx context.Context, _ *struct{}) (*ListRegistriesOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	filter := service.VisibilityFilter{
		IsAdmin: user.Role == roleAdmin,
		UserID:  user.ID,
	}
	regs, err := h.registryService.List(ctx, filter)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing registries: %v", err))
	}
	out := &ListRegistriesOutput{}
	out.Body.Registries = make([]RegistryResponse, len(regs))
	for i, r := range regs {
		out.Body.Registries[i] = toRegistryResponse(r, h.cfg.APIBaseURL)
	}
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
	return &GetRegistryOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL)}, nil
}

// CreateRegistry creates a new registry. Any authenticated user can create.
// For webhook-capable registries, a secret is auto-generated if not provided and returned once in the response.
func (h *Handler) CreateRegistry(ctx context.Context, in *CreateRegistryInput) (*CreateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	scanMode := in.Body.ScanMode
	if scanMode == "" {
		scanMode = "webhook"
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
	if (scanMode == "webhook" || scanMode == "both") && (webhookSecret == nil || *webhookSecret == "") {
		s, err := generateWebhookSecret()
		if err != nil {
			return nil, huma.Error500InternalServerError("generating webhook secret")
		}
		generatedSecret = s
		webhookSecret = &generatedSecret
	}

	reg, err := h.registryService.Create(ctx, in.Body.Name, in.Body.Type, in.Body.URL, in.Body.Insecure, webhookSecret, in.Body.Repositories, in.Body.RepositoryPatterns, in.Body.TagPatterns, scanMode, pollInterval, in.Body.AuthUsername, in.Body.AuthToken, user.ID, visibility, in.Body.IncludeUntagged)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("creating registry: %v", err))
	}
	return &CreateRegistryOutput{Body: CreateRegistryResponseBody{
		RegistryResponse: toRegistryResponse(reg, h.cfg.APIBaseURL),
		WebhookSecret:    generatedSecret,
	}}, nil
}

// RegenerateWebhookSecret generates a new webhook secret for a registry (owner or admin).
// The previous secret is immediately invalidated.
func (h *Handler) RegenerateWebhookSecret(ctx context.Context, in *RegenerateWebhookSecretInput) (*RegenerateWebhookSecretOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if !canManageRegistry(user, existing) {
		return nil, huma.Error403Forbidden("only the owner or an admin can update this registry")
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
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if !canManageRegistry(user, existing) {
		return nil, huma.Error403Forbidden("only the owner or an admin can update this registry")
	}
	scanMode := in.Body.ScanMode
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
	reg, err := h.registryService.Update(ctx, in.ID, in.Body.Name, in.Body.Type, in.Body.URL, in.Body.Insecure, existing.WebhookSecret, in.Body.Enabled, in.Body.Repositories, in.Body.RepositoryPatterns, in.Body.TagPatterns, scanMode, pollInterval, in.Body.AuthUsername, in.Body.AuthToken, visibility, in.Body.IncludeUntagged)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &UpdateRegistryOutput{Body: toRegistryResponse(reg, h.cfg.APIBaseURL)}, nil
}

// DeleteRegistry deletes a registry (owner or admin).
func (h *Handler) DeleteRegistry(ctx context.Context, in *DeleteRegistryInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	existing, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if !canManageRegistry(user, existing) {
		return nil, huma.Error403Forbidden("only the owner or an admin can delete this registry")
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
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if !canManageRegistry(user, reg) {
		return nil, huma.Error403Forbidden("only the owner or an admin can scan this registry")
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
		OwnerID:             r.OwnerID,
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
