package api

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/scanner"
)

// zotEvent is the payload Zot sends for image push/update events.
type zotEvent struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Manifest  string `json:"manifest"`
}

// ZotWebhookInput is the huma input type for the Zot webhook handler.
type ZotWebhookInput struct {
	Authorization string   `header:"Authorization"`
	Body          zotEvent
}

// HandleZotWebhook receives Zot registry push notifications.
func (h *Handler) HandleZotWebhook(ctx context.Context, in *ZotWebhookInput) (*struct{}, error) {
	// Validate bearer token if a secret is configured.
	if h.webhookSecret != "" {
		token := strings.TrimPrefix(in.Authorization, "Bearer ")
		if token != h.webhookSecret {
			return nil, huma.Error401Unauthorized("invalid webhook secret")
		}
	}

	ev := in.Body

	// Only scan standard image manifests; skip indexes, attestations, and other artifact types.
	switch ev.MediaType {
	case "application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json":
		// scannable
	default:
		return nil, nil
	}

	if h.scannerDispatcher == nil {
		return nil, huma.Error503ServiceUnavailable("scanner not enabled")
	}

	h.scannerDispatcher.Submit(scanner.ScanRequest{
		Repository: ev.Name,
		Digest:     ev.Digest,
		Tag:        ev.Reference,
	})

	return nil, nil
}
