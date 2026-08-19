package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// clusterIngestTimeout bounds the registry round-trips for one image. A running
// cluster can report hundreds of unknown images, and a registry that hangs must
// cost one image's worth of delay rather than the whole run's.
const clusterIngestTimeout = 15 * time.Second

// ClusterIngestor submits scan jobs for images a Kubernetes cluster reports as
// running (ADR-044). It satisfies service.RunningImageSubmitter.
type ClusterIngestor struct {
	submitter Submitter
	logger    *slog.Logger
}

// NewClusterIngestor constructs a ClusterIngestor over an existing submitter,
// so cluster ingest shares the scan queue — and its (registry, digest)
// idempotency key — with the catalog walk rather than opening a second path.
func NewClusterIngestor(sub Submitter, logger *slog.Logger) *ClusterIngestor {
	if logger == nil {
		logger = slog.Default()
	}
	return &ClusterIngestor{submitter: sub, logger: logger}
}

// SubmitForRunningImage queues a scan for one running image, returning the
// number of scan jobs enqueued.
func (c *ClusterIngestor) SubmitForRunningImage(ctx context.Context, reg service.Registry, repo, digest, tag string) (int, error) {
	return SubmitForRunningImage(ctx, reg, repo, digest, tag, c.submitter, c.logger)
}

// SubmitForRunningImage queues a scan for one image a cluster is running.
//
// The digest a cluster reports is whatever containerd resolved the reference
// to, which for a multi-arch image is the *index* digest (ADR-044). Submitting
// that digest as-is would enqueue a manifest list the scanner cannot read as an
// image, so an index is expanded here into one job per platform, exactly as the
// catalog walk does — the resulting jobs are then indistinguishable from
// walk-produced ones, which is what lets the same worker handle both.
//
// Returns the number of jobs enqueued: one for a single-arch image, one per
// platform for an index, zero when the registry declines the repository.
func SubmitForRunningImage(ctx context.Context, reg service.Registry, repo, digest, tag string, sub Submitter, logger *slog.Logger) (int, error) {
	if sub == nil {
		return 0, fmt.Errorf("no scan submitter configured")
	}
	// Re-checked here rather than trusted from the caller: this is the function
	// that actually reaches a registry with its credentials, so it is where a
	// disabled registry or an excluded repository has to stop.
	if !reg.Enabled {
		return 0, nil
	}
	if !reg.MatchesRepository(repo) {
		return 0, nil
	}
	if repo == "" || digest == "" {
		return 0, fmt.Errorf("image has no repository or digest to scan")
	}

	scheme, host := registrySchemeHost(reg)
	baseURL := scheme + "://" + host
	client := &http.Client{
		Timeout:   clusterIngestTimeout,
		Transport: newOCITokenTransport(derefStr(reg.AuthUsername), derefStr(reg.AuthToken)),
	}

	info, err := ociHeadManifest(ctx, client, baseURL, repo, digest)
	if err != nil {
		return 0, fmt.Errorf("HEAD %s@%s: %w", repo, digest, err)
	}
	if isIndexMediaType(info.mediaType) {
		return submitRunningIndex(ctx, client, baseURL, repo, digest, tag, reg, sub, logger), nil
	}
	if !isImageManifestType(info.mediaType) {
		logger.Debug("cluster image is not a scannable manifest",
			"repo", repo, "digest", digest, "mediaType", info.mediaType)
		return 0, nil
	}

	meta := ociGetImageMetadata(ctx, client, baseURL, repo, digest)
	if err := sub.Submit(ctx, ScanRequest{
		RegistryURL:  reg.URL,
		Insecure:     reg.Insecure,
		Repository:   repo,
		Digest:       digest,
		Tag:          tag,
		Architecture: meta.architecture,
		BuildDate:    meta.buildDate,
		ImageVersion: meta.imageVersion,
		AuthUsername: derefStr(reg.AuthUsername),
		AuthToken:    derefStr(reg.AuthToken),
		RegistryID:   reg.ID,
	}); err != nil {
		return 0, fmt.Errorf("submitting scan for %s@%s: %w", repo, digest, err)
	}
	return 1, nil
}

// submitRunningIndex expands the index a cluster reported and submits one job
// per platform, recording the index digest on each so a workload matched by
// index digest still resolves (ADR-044 tier two).
func submitRunningIndex(ctx context.Context, client *http.Client, baseURL, repo, indexDigest, tag string, reg service.Registry, sub Submitter, logger *slog.Logger) int {
	platforms, err := ociExpandIndex(ctx, client, baseURL, repo, indexDigest)
	if err != nil {
		logger.Warn("expanding running image index", "repo", repo, "digest", indexDigest, "err", err)
		return 0
	}
	queued := 0
	for _, p := range platforms {
		meta := ociGetImageMetadata(ctx, client, baseURL, repo, p.digest)
		if meta.attachedArtifact {
			continue
		}
		arch := p.arch
		if arch == "" {
			arch = meta.architecture
		}
		if err := sub.Submit(ctx, ScanRequest{
			RegistryURL:  reg.URL,
			Insecure:     reg.Insecure,
			Repository:   repo,
			Digest:       p.digest,
			IndexDigest:  indexDigest,
			Tag:          tag,
			Architecture: arch,
			BuildDate:    meta.buildDate,
			ImageVersion: meta.imageVersion,
			AuthUsername: derefStr(reg.AuthUsername),
			AuthToken:    derefStr(reg.AuthToken),
			RegistryID:   reg.ID,
		}); err != nil {
			logger.Warn("scan submit failed", "repo", repo, "digest", p.digest, "err", err)
			continue
		}
		queued++
	}
	return queued
}
