package api

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/scanner"
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

	if reg.WebhookSecret != nil && *reg.WebhookSecret != "" {
		token := strings.TrimPrefix(in.Authorization, "Bearer ")
		if token != *reg.WebhookSecret {
			return nil, huma.Error401Unauthorized("invalid webhook secret")
		}
	}

	// Only scan standard image manifests; skip indexes, attestations, and other artifact types.
	switch in.Body.MediaType {
	case "application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json":
		// scannable
	default:
		return nil, nil
	}

	// Apply registry-level ingestion filters.
	if !reg.MatchesImage(in.Body.Name, in.Body.Reference) {
		return nil, nil
	}

	if h.scanSubmitter == nil {
		return nil, huma.Error503ServiceUnavailable("scanner not enabled")
	}

	h.scanSubmitter.Submit(scanner.ScanRequest{
		RegistryURL: reg.URL,
		Insecure:    reg.Insecure,
		Repository:  in.Body.Name,
		Digest:      in.Body.Digest,
		Tag:         in.Body.Reference,
	})

	return nil, nil
}
