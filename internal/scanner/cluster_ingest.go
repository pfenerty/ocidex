package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/pfenerty/ocidex/internal/netguard"
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
	egress    netguard.Policy
	logger    *slog.Logger
}

// NewClusterIngestor constructs a ClusterIngestor over an existing submitter,
// so cluster ingest shares the scan queue — and its (registry, digest)
// idempotency key — with the catalog walk rather than opening a second path.
func NewClusterIngestor(sub Submitter, egress netguard.Policy, logger *slog.Logger) *ClusterIngestor {
	if logger == nil {
		logger = slog.Default()
	}
	return &ClusterIngestor{submitter: sub, egress: egress, logger: logger}
}

// SubmitForRunningImage queues a scan for one running image, returning the
// number of scan jobs enqueued.
func (c *ClusterIngestor) SubmitForRunningImage(ctx context.Context, target service.RunningImageTarget, repo, digest, tag string) (int, error) {
	return SubmitForRunningImage(ctx, target, repo, digest, tag, c.submitter, c.egress, c.logger)
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
// target.Registry nil pulls anonymously over HTTPS from target.Host, through
// the same egress policy as registry traffic: a cluster-reported reference is
// input a cluster key controls (ADR-0044 K10). A refusal that asking again
// will not fix comes back as a *service.IngestRefusedError.
//
// Returns the number of jobs enqueued: one for a single-arch image, one per
// platform for an index, zero when the registry declines the repository.
func SubmitForRunningImage(ctx context.Context, target service.RunningImageTarget, repo, digest, tag string, sub Submitter, egress netguard.Policy, logger *slog.Logger) (int, error) {
	if sub == nil {
		return 0, fmt.Errorf("no scan submitter configured")
	}
	reg := service.Registry{URL: schemeHTTPS + "://" + target.Host, Enabled: true}
	if target.Registry != nil {
		reg = *target.Registry
		// Re-checked here rather than trusted from the caller: this is the
		// function that actually reaches a registry with its credentials, so
		// it is where a disabled registry has to stop. An excluded repository
		// stops here too, unless the job is the cluster's: then the patterns,
		// which scope the catalog walk, do not apply.
		if !reg.Enabled {
			return 0, nil
		}
		if target.ClusterID == "" && !reg.ClaimsRepository(repo) {
			return 0, nil
		}
	}
	if repo == "" || digest == "" {
		return 0, fmt.Errorf("image has no repository or digest to scan")
	}

	scheme, host := registrySchemeHost(reg)
	baseURL := scheme + "://" + host
	client := registryClient(egress, clusterIngestTimeout, derefStr(reg.AuthUsername), derefStr(reg.AuthToken))
	base := ScanRequest{
		RegistryURL:  reg.URL,
		Insecure:     reg.Insecure,
		Repository:   repo,
		Tag:          tag,
		AuthUsername: derefStr(reg.AuthUsername),
		AuthToken:    derefStr(reg.AuthToken),
		RegistryID:   reg.ID,
		ClusterID:    target.ClusterID,
	}

	info, err := ociHeadManifest(ctx, client, baseURL, repo, digest)
	if err != nil {
		return 0, classifyPullError(fmt.Errorf("HEAD %s@%s: %w", repo, digest, err))
	}
	if isIndexMediaType(info.mediaType) {
		return submitRunningIndex(ctx, client, baseURL, digest, base, sub, logger), nil
	}
	if !isImageManifestType(info.mediaType) {
		logger.Debug("cluster image is not a scannable manifest",
			"repo", repo, "digest", digest, "mediaType", info.mediaType)
		return 0, nil
	}

	meta := ociGetImageMetadata(ctx, client, baseURL, repo, digest)
	req := base
	req.Digest = digest
	req.Architecture = meta.architecture
	req.BuildDate = meta.buildDate
	req.ImageVersion = meta.imageVersion
	if err := sub.Submit(ctx, req); err != nil {
		return 0, fmt.Errorf("submitting scan for %s@%s: %w", repo, digest, err)
	}
	return 1, nil
}

// classifyPullError marks the failures asking again will not fix: a refusal
// (401/403, after the anonymous token exchange), a refused address, and a
// manifest the host does not have. Anything else stays a plain error.
func classifyPullError(err error) error {
	var status *httpStatusError
	switch {
	case errors.Is(err, netguard.ErrDenied):
		return &service.IngestRefusedError{Reason: service.IngestReasonEgressDenied, Err: err}
	case errors.As(err, &status) && (status.code == http.StatusUnauthorized || status.code == http.StatusForbidden):
		return &service.IngestRefusedError{Reason: service.IngestReasonUnauthorized, Err: err}
	case errors.As(err, &status) && status.code == http.StatusNotFound:
		return &service.IngestRefusedError{Reason: service.IngestRefusalNotFound, Err: err}
	}
	return err
}

// submitRunningIndex expands the index a cluster reported and submits one job
// per platform, recording the index digest on each so a workload matched by
// index digest still resolves (ADR-044 tier two).
func submitRunningIndex(ctx context.Context, client *http.Client, baseURL, indexDigest string, base ScanRequest, sub Submitter, logger *slog.Logger) int {
	repo := base.Repository
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
		req := base
		req.Digest = p.digest
		req.IndexDigest = indexDigest
		req.Architecture = p.arch
		if req.Architecture == "" {
			req.Architecture = meta.architecture
		}
		req.BuildDate = meta.buildDate
		req.ImageVersion = meta.imageVersion
		if err := sub.Submit(ctx, req); err != nil {
			logger.Warn("scan submit failed", "repo", repo, "digest", p.digest, "err", err)
			continue
		}
		queued++
	}
	return queued
}
