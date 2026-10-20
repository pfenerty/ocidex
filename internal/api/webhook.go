package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// HandleRegistryWebhook receives push notifications from a configured registry.
func (h *Handler) HandleRegistryWebhook(ctx context.Context, in *RegistryWebhookInput) (*struct{}, error) {
	if h.registryService == nil {
		return nil, huma.Error503ServiceUnavailable("registry service not configured")
	}

	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}

	if !reg.Enabled {
		return nil, huma.Error503ServiceUnavailable("registry disabled")
	}

	if !reg.AcceptsWebhooks() {
		// Poll-only registry: accept silently without scanning.
		return nil, nil
	}

	if reg.WebhookSecret == nil || *reg.WebhookSecret == "" {
		return nil, huma.Error401Unauthorized("webhook secret not configured")
	}
	token := strings.TrimPrefix(in.Authorization, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(*reg.WebhookSecret)) != 1 {
		return nil, huma.Error401Unauthorized("invalid webhook secret")
	}

	if !h.webhookWantsScan(ctx, reg, in) {
		return nil, nil
	}

	if h.scanSubmitter == nil {
		return nil, huma.Error503ServiceUnavailable("scanner not enabled")
	}

	var authUsername, authToken string
	if reg.AuthUsername != nil {
		authUsername = *reg.AuthUsername
	}
	if reg.AuthToken != nil {
		authToken = *reg.AuthToken
	}
	if err := h.scanSubmitter.Submit(ctx, scanner.ScanRequest{
		RegistryURL:  reg.URL,
		Insecure:     reg.Insecure,
		Repository:   in.Body.Name,
		Digest:       in.Body.Digest,
		Tag:          in.Body.Reference,
		AuthUsername: authUsername,
		AuthToken:    authToken,
		RegistryID:   reg.ID,
	}); err != nil {
		return nil, huma.Error503ServiceUnavailable("scan submit failed")
	}

	return nil, nil
}

// webhookWantsScan applies the push filters in order: a scannable manifest
// type, not an attached artifact, the registry's repository and tag filters,
// and its scan window (ADR-0053 S8).
func (h *Handler) webhookWantsScan(ctx context.Context, reg service.Registry, in *RegistryWebhookInput) bool {
	// Only scan standard image manifests; skip indexes, attestations, and other artifact types.
	switch in.Body.MediaType {
	case "application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json":
		// scannable
	default:
		return false
	}

	// Cosign signatures and attestations pass the check above — they are image
	// manifests — but syft cannot catalog their signature-payload layers. The
	// tag is the only signal available here (ocidex-ptj2).
	if scanner.IsAttachedArtifactTag(in.Body.Reference) {
		return false
	}

	// Apply registry-level ingestion filters.
	if !reg.MatchesImage(in.Body.Name, in.Body.Reference) {
		return false
	}
	// And the scan window (ADR-0053 S8), so a push of an old tag does not scan
	// what the walk deliberately leaves out. If the tag list cannot be read the
	// push is scanned: it is almost always the newest build, and dropping it
	// would hide a registry outage behind a silent 204.
	inWindow, err := scanner.TagInWindow(ctx, reg, in.Body.Name, in.Body.Reference, h.egress(), slog.Default())
	if err != nil {
		slog.Warn("webhook: scan window unavailable, scanning the push", "registry", reg.Name, "repo", in.Body.Name, "err", err)
	} else if !inWindow {
		return false
	}
	return true
}
