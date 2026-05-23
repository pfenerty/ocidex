package scanner

import (
	"context"
	"net/http"
)

// FillMetadata populates Architecture, BuildDate, and ImageVersion on req by
// reading the registry manifest/config. Only empty fields are filled; populated
// fields are left untouched. Network or parse failures yield empty strings.
//
// Used by the in-process scan dispatcher to backfill metadata for
// webhook-triggered requests, which (unlike catalog-walk requests) don't
// pre-fetch this from the registry index.
func FillMetadata(ctx context.Context, req ScanRequest) ScanRequest {
	if req.Architecture != "" && req.BuildDate != "" && req.ImageVersion != "" {
		return req
	}
	scheme := "https"
	if req.Insecure {
		scheme = "http"
	}
	baseURL := scheme + "://" + normalizeRegistryHost(req.RegistryURL)
	client := &http.Client{Transport: newOCITokenTransport(req.AuthUsername, req.AuthToken)}
	meta := ociGetImageMetadata(ctx, client, baseURL, req.Repository, req.Digest)
	if req.Architecture == "" {
		req.Architecture = meta.architecture
	}
	if req.BuildDate == "" {
		req.BuildDate = meta.buildDate
	}
	if req.ImageVersion == "" {
		req.ImageVersion = meta.imageVersion
	}
	return req
}
