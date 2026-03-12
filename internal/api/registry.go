package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// ListRegistries returns all configured registries (admin only).
func (h *Handler) ListRegistries(ctx context.Context, _ *struct{}) (*ListRegistriesOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
	}
	regs, err := h.registryService.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing registries: %v", err))
	}
	out := &ListRegistriesOutput{}
	out.Body.Registries = make([]RegistryResponse, len(regs))
	for i, r := range regs {
		out.Body.Registries[i] = toRegistryResponse(r)
	}
	return out, nil
}

// GetRegistry returns a single registry by ID (admin only).
func (h *Handler) GetRegistry(ctx context.Context, in *GetRegistryInput) (*GetRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &GetRegistryOutput{Body: toRegistryResponse(reg)}, nil
}

// CreateRegistry creates a new registry (admin only).
func (h *Handler) CreateRegistry(ctx context.Context, in *CreateRegistryInput) (*CreateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
	}
	scanMode := in.Body.ScanMode
	if scanMode == "" {
		scanMode = "webhook"
	}
	pollInterval := in.Body.PollIntervalMinutes
	if pollInterval == 0 {
		pollInterval = 60
	}
	reg, err := h.registryService.Create(ctx, in.Body.Name, in.Body.Type, in.Body.URL, in.Body.Insecure, in.Body.WebhookSecret, in.Body.Repositories, in.Body.RepositoryPatterns, in.Body.TagPatterns, scanMode, pollInterval)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("creating registry: %v", err))
	}
	return &CreateRegistryOutput{Body: toRegistryResponse(reg)}, nil
}

// UpdateRegistry updates a registry (admin only).
func (h *Handler) UpdateRegistry(ctx context.Context, in *UpdateRegistryInput) (*UpdateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
	}
	scanMode := in.Body.ScanMode
	if scanMode == "" {
		scanMode = "webhook"
	}
	pollInterval := in.Body.PollIntervalMinutes
	if pollInterval == 0 {
		pollInterval = 60
	}
	reg, err := h.registryService.Update(ctx, in.ID, in.Body.Name, in.Body.Type, in.Body.URL, in.Body.Insecure, in.Body.WebhookSecret, in.Body.Enabled, in.Body.Repositories, in.Body.RepositoryPatterns, in.Body.TagPatterns, scanMode, pollInterval)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &UpdateRegistryOutput{Body: toRegistryResponse(reg)}, nil
}

// DeleteRegistry deletes a registry (admin only).
func (h *Handler) DeleteRegistry(ctx context.Context, in *DeleteRegistryInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
	}
	if err := h.registryService.Delete(ctx, in.ID); err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return nil, nil
}

// TestRegistryConnection probes the registry's /v2/ endpoint (admin only).
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

	resp, err := c.Do(req)
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

// ScanRegistry triggers an ad-hoc catalog walk of a registry (admin only).
// It runs asynchronously and returns immediately.
func (h *Handler) ScanRegistry(ctx context.Context, in *ScanRegistryInput) (*ScanRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return nil, huma.Error403Forbidden("admin only")
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
		queued, err := scanner.WalkRegistry(walkCtx, reg, h.scanSubmitter, slog.Default())
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

func toRegistryResponse(r service.Registry) RegistryResponse {
	rr := RegistryResponse{
		ID:                  r.ID,
		Name:                r.Name,
		Type:                r.Type,
		URL:                 r.URL,
		Insecure:            r.Insecure,
		HasSecret:           r.WebhookSecret != nil && *r.WebhookSecret != "",
		Enabled:             r.Enabled,
		WebhookPath:         "/api/v1/webhooks/" + r.ID,
		Repositories:        r.Repositories,
		RepositoryPatterns:  r.RepositoryPatterns,
		TagPatterns:         r.TagPatterns,
		ScanMode:            r.ScanMode,
		PollIntervalMinutes: r.PollIntervalMinutes,
		CreatedAt:           r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:           r.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
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
