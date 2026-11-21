package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
)

func extensionNames(cfg *config.Config) []string {
	exts := ingestExtensions(cfg, nil, slog.Default())
	names := make([]string, 0, len(exts))
	for _, ext := range exts {
		names = append(names, ext.Name())
	}
	return names
}

// Registry scans are ingested here, not in the API, so the scanner worker has
// to carry the audit extension itself (ocidex-5fiq).
func TestIngestExtensionsIncludeAuditWhenEnabled(t *testing.T) {
	is := is.New(t)
	names := extensionNames(&config.Config{AuditLogEnabled: true, NATSStreamName: "ocidex"})
	is.True(strings.Contains(strings.Join(names, ","), "audit"))
}

func TestIngestExtensionsOmitAuditWhenDisabled(t *testing.T) {
	is := is.New(t)
	names := extensionNames(&config.Config{AuditLogEnabled: false, NATSStreamName: "ocidex"})
	is.True(!strings.Contains(strings.Join(names, ","), "audit"))
	is.Equal(len(names), 1) // the enrichment submitter stays
}

// The audit extension this process registers writes the sbom.ingested line
// when an ingest publishes on the bus.
func TestIngestExtensionsAuditLineOnIngest(t *testing.T) {
	is := is.New(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	bus := event.NewBus(logger)
	for _, ext := range ingestExtensions(&config.Config{AuditLogEnabled: true}, nil, logger) {
		if ext.Name() == "audit" {
			is.NoErr(ext.Init(bus))
		}
	}
	bus.Publish(context.Background(), event.SBOMIngested, event.SBOMIngestedData{ArtifactName: "ghcr.io/acme/api"})
	is.True(strings.Contains(buf.String(), `"msg":"audit"`))
	is.True(strings.Contains(buf.String(), `"event_type":"sbom.ingested"`))
}

func TestParseImageRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	tests := []struct {
		ref                         string
		wantHost, wantRepo, wantTag string
		wantErr                     bool
	}{
		{ref: "ghcr.io/acme/api@" + digest, wantHost: "ghcr.io", wantRepo: "acme/api"},
		{ref: "ghcr.io/acme/api:1.4@" + digest, wantHost: "ghcr.io", wantRepo: "acme/api", wantTag: "1.4"},
		{ref: "registry.local:5000/acme/api:dev@" + digest, wantHost: "registry.local:5000", wantRepo: "acme/api", wantTag: "dev"},
		{ref: "docker.io/library/nginx@" + digest, wantHost: "registry-1.docker.io", wantRepo: "library/nginx"},
		{ref: "ghcr.io/acme/api:1.4", wantErr: true},    // no digest
		{ref: "library/nginx@" + digest, wantErr: true}, // no registry host
		{ref: "ghcr.io/acme/api@sha256:abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			is := is.New(t)
			host, repo, dig, tag, err := parseImageRef(tt.ref)
			if tt.wantErr {
				is.True(err != nil)
				return
			}
			is.NoErr(err)
			is.Equal(host, tt.wantHost)
			is.Equal(repo, tt.wantRepo)
			is.Equal(dig, digest)
			is.Equal(tag, tt.wantTag)
		})
	}
}
