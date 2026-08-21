package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Reasons an unknown image cannot be turned into a scan job. They are reported
// rather than retried, because each has a different remedy and none of them is
// fixed by asking again (ADR-044).
const (
	// IngestReasonReady means a registry in the cluster's namespace serves this
	// image and accepts its repository: ingesting it is possible right now.
	IngestReasonReady = "ready"
	// IngestReasonNoRegistry means no registry in the cluster's namespace is
	// configured for the image's host. The remedy is to add one.
	IngestReasonNoRegistry = "no_registry"
	// IngestReasonRegistryDisabled means the host matches a registry that is
	// switched off. The remedy is to enable it, not to add another.
	IngestReasonRegistryDisabled = "registry_disabled"
	// IngestReasonPatternExcluded means the registry's repository patterns
	// deliberately exclude this repository. Nothing is broken; the exclusion is
	// reported so it does not look like a failure.
	IngestReasonPatternExcluded = "pattern_excluded"
	// IngestReasonUnparseableRef means the reported reference has no host, so
	// there is nothing to resolve against. This overlaps with the K3 gap: a
	// runtime reporting a bare identifier gives no registry to ask.
	IngestReasonUnparseableRef = "unparseable_ref"
)

// UnknownImage is one image running in a cluster with no ingested SBOM,
// together with whether OCIDex could do anything about it.
//
// It is grouped by image rather than by container because that is the unit of
// the remedy: twelve replicas of one unscanned image are one thing to ingest.
type UnknownImage struct {
	ImageRef      string
	ImageDigest   string
	RegistryHost  string // normalized host parsed out of ImageRef; "" if none
	Repository    string // repository path within that host
	Tag           string // tag on the reference; "" when it carries only a digest
	WorkloadCount int64
	PodCount      int64
	// SampleK8sNamespace and SampleWorkloadName name one workload running the
	// image, so a row is recognisable without expanding it.
	SampleK8sNamespace string
	SampleWorkloadName string

	// Reason is one of the IngestReason constants. RegistryID and RegistryName
	// are set whenever a registry was matched at all — including when it is
	// disabled or excludes the repository, because naming the registry is what
	// makes those two reasons actionable.
	Reason       string
	RegistryID   *string
	RegistryName *string
}

// Ingestable reports whether a scan job can be submitted for this image now.
func (u UnknownImage) Ingestable() bool { return u.Reason == IngestReasonReady }

// UnknownImages lists the cluster's No-SBOM gap, each image resolved against
// the registries of the cluster's own namespace.
//
// Resolution is deliberately namespace-local. A registry in another namespace
// could well serve the host, but using it would let one namespace's cluster
// trigger pulls with another namespace's credentials.
func (s *clusterService) UnknownImages(ctx context.Context, clusterID string, limit int32, filter VisibilityFilter) ([]UnknownImage, error) {
	images, _, err := s.resolveUnknownImages(ctx, clusterID, limit, filter)
	return images, err
}

// resolveUnknownImages does the work behind both UnknownImages and
// IngestUnknown, and additionally returns the registries it resolved against
// keyed by id. Ingest needs the whole Registry — URL, credentials, insecure
// flag — where the listing needs only its name; running one resolver for both
// is what keeps the gap list's promise and the ingest attempt from drifting.
func (s *clusterService) resolveUnknownImages(ctx context.Context, clusterID string, limit int32, filter VisibilityFilter) ([]UnknownImage, map[string]Registry, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	// The cluster read is what enforces visibility on the namespace lookup
	// below: without it, an unauthorized caller could learn a namespace's
	// registry names through this endpoint.
	cluster, err := s.Get(ctx, clusterID)
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.repo.ListClusterUnknownImages(ctx, repository.ListClusterUnknownImagesParams{
		ClusterID: cid,
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
		// A NULL limit is no limit, which is what ingest wants: the gap list
		// is a page, the ingest is the whole gap.
		Limit: pgtype.Int4{Int32: limit, Valid: limit > 0},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing unknown cluster images: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}

	nsID, err := parseUUID(cluster.NamespaceID)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	regRows, err := s.repo.ListRegistriesByNamespace(ctx, nsID)
	if err != nil {
		return nil, nil, fmt.Errorf("listing namespace registries: %w", err)
	}
	registries := make([]Registry, len(regRows))
	byID := make(map[string]Registry, len(regRows))
	for i, r := range regRows {
		registries[i] = fromRepo(registryComposite{
			reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
		})
		byID[registries[i].ID] = registries[i]
	}

	out := make([]UnknownImage, len(rows))
	for i, r := range rows {
		host, repo := SplitImageRef(r.ImageRef)
		img := UnknownImage{
			ImageRef:           r.ImageRef,
			ImageDigest:        r.ImageDigest,
			RegistryHost:       host,
			Repository:         repo,
			Tag:                imageRefTag(r.ImageRef),
			WorkloadCount:      r.WorkloadCount,
			PodCount:           r.PodCount,
			SampleK8sNamespace: r.SampleK8sNamespace,
			SampleWorkloadName: r.SampleWorkloadName,
		}
		resolveIngestTarget(&img, registries)
		out[i] = img
	}
	return out, byID, nil
}

// resolveIngestTarget picks the registry that serves img and records why it
// cannot be ingested when it cannot.
//
// An enabled registry that accepts the repository wins outright. Otherwise the
// first host match is kept anyway so the reason can name it: "ghcr is switched
// off" and "no registry for ghcr.io" are different problems and must not both
// report as the latter.
func resolveIngestTarget(img *UnknownImage, registries []Registry) {
	if img.RegistryHost == "" {
		img.Reason = IngestReasonUnparseableRef
		return
	}
	img.Reason = IngestReasonNoRegistry
	for _, reg := range registries {
		if reg.Host() != img.RegistryHost {
			continue
		}
		switch {
		case !reg.Enabled:
			img.setRegistry(reg, IngestReasonRegistryDisabled)
		case !reg.MatchesRepository(img.Repository):
			img.setRegistry(reg, IngestReasonPatternExcluded)
		default:
			img.setRegistry(reg, IngestReasonReady)
			return
		}
	}
}

// setRegistry names the matched registry, keeping the first match for any
// non-ready reason so a later, worse match cannot overwrite it.
func (u *UnknownImage) setRegistry(reg Registry, reason string) {
	if u.RegistryID != nil && reason != IngestReasonReady {
		return
	}
	id, name := reg.ID, reg.Name
	u.RegistryID, u.RegistryName, u.Reason = &id, &name, reason
}

// Host returns the registry's URL reduced to a comparable hostname.
func (r Registry) Host() string { return NormalizeRegistryHost(r.URL) }

// NormalizeRegistryHost strips any scheme and trailing slash from a registry URL
// and maps the Docker Hub aliases onto the one host that actually serves the
// API, so a registry configured as "docker.io" matches an image reference that
// names "index.docker.io".
func NormalizeRegistryHost(host string) string {
	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}
	host = strings.TrimSuffix(host, "/")
	switch host {
	case "docker.io", "index.docker.io", "hub.docker.com":
		return "registry-1.docker.io"
	}
	return host
}

// SplitImageRef splits a running container's image reference into its normalized
// registry host and repository path, dropping any tag or digest.
//
// A reference with no host segment ("nginx", "library/nginx") returns an empty
// host rather than guessing Docker Hub. Guessing would produce an ingest attempt
// against a registry the cluster may not use at all, and the caller reports an
// unresolved host as its own remedy.
func SplitImageRef(ref string) (host, repo string) {
	if at := strings.LastIndex(ref, "@"); at != -1 {
		ref = ref[:at]
	}
	host, repo, found := strings.Cut(ref, "/")
	if !found {
		return "", ""
	}
	// The first segment is only a host if it looks like one. "library/nginx"
	// has a slash but no registry in it.
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return "", ""
	}
	if colon := strings.LastIndex(repo, ":"); colon != -1 && !strings.Contains(repo[colon:], "/") {
		repo = repo[:colon]
	}
	return NormalizeRegistryHost(host), repo
}

// imageRefTag returns the tag on a running image reference, or "" when the
// reference carries only a digest.
//
// The tag is carried into the scan job for logging and version metadata only.
// Identity is always the digest: a tag is mutable and the cluster reported one
// specific thing to be running.
func imageRefTag(ref string) string {
	if at := strings.LastIndex(ref, "@"); at != -1 {
		ref = ref[:at]
	}
	colon := strings.LastIndex(ref, ":")
	if colon == -1 || colon < strings.LastIndex(ref, "/") {
		return ""
	}
	return ref[colon+1:]
}

// RunningImageSubmitter turns one running image into scan jobs, returning how
// many it queued. A multi-arch image expands into one job per platform, so the
// count is not always one.
//
// The interface lives in service because internal/scanner imports this package
// and not the other way round; scanner.ClusterIngestor implements it.
type RunningImageSubmitter interface {
	SubmitForRunningImage(ctx context.Context, reg Registry, repo, digest, tag string) (int, error)
}

// IngestResult accounts for every unknown image an ingest run considered.
//
// The skips are counted per reason rather than summed. "Nothing was queued"
// and "nothing could be queued because no registry serves ghcr.io" are the same
// number and different problems, and each reason has its own remedy (ADR-044).
type IngestResult struct {
	// Considered is every unknown image looked at, so the counts below can be
	// read as a complete accounting rather than a sample.
	Considered              int
	Queued                  int
	SkippedNoRegistry       int
	SkippedRegistryDisabled int
	SkippedPatternExcluded  int
	SkippedUnparseableRef   int
	// Failed counts images whose registry accepted them but whose submission
	// errored — a transient registry or queue problem, not a configuration one.
	Failed int
}

// IngestUnknownParams narrows an ingest run.
type IngestUnknownParams struct {
	// ImageDigests, when non-empty, limits the run to those images. Empty means
	// the whole gap, which is what the snapshot trigger wants; the per-row
	// button in the UI passes one digest so the button does what it says
	// rather than quietly queueing the cluster.
	ImageDigests []string
}

// IngestUnknown submits a scan job for every running image with no SBOM whose
// host resolves to an enabled registry in the cluster's own namespace.
//
// Repeat runs are free: the submitter keys scan jobs on (registry, digest), so
// a snapshot that reports the same unscanned images again enqueues nothing new.
// That is what makes it safe to fire this on every push.
func (s *clusterService) IngestUnknown(ctx context.Context, clusterID string, sub RunningImageSubmitter, params IngestUnknownParams, filter VisibilityFilter) (IngestResult, error) {
	if sub == nil {
		return IngestResult{}, &ValidationError{Message: "scanning is not enabled on this deployment"}
	}
	// No limit: this is the whole gap, not a page of it.
	images, registries, err := s.resolveUnknownImages(ctx, clusterID, 0, filter)
	if err != nil {
		return IngestResult{}, err
	}

	// Filtering here rather than in SQL keeps one resolver for both callers:
	// a digest the caller names but the cluster is not running unknown simply
	// matches nothing, which is the right answer for a stale button.
	if len(params.ImageDigests) > 0 {
		wanted := make(map[string]bool, len(params.ImageDigests))
		for _, d := range params.ImageDigests {
			wanted[d] = true
		}
		kept := images[:0]
		for _, img := range images {
			if wanted[img.ImageDigest] {
				kept = append(kept, img)
			}
		}
		images = kept
	}

	var res IngestResult
	res.Considered = len(images)
	for _, img := range images {
		if !img.Ingestable() {
			res.countSkip(img.Reason)
			continue
		}
		var regID string
		if img.RegistryID != nil {
			regID = *img.RegistryID
		}
		reg, ok := registries[regID]
		if !ok {
			// resolveIngestTarget only reports ready against a registry it
			// found, so this cannot happen; count it rather than panicking on
			// a future refactor that makes it possible.
			res.SkippedNoRegistry++
			continue
		}
		queued, err := sub.SubmitForRunningImage(ctx, reg, img.Repository, img.ImageDigest, img.Tag)
		if err != nil {
			// One unreachable registry must not abandon the images served by
			// the others.
			res.Failed++
			continue
		}
		res.Queued += queued
	}
	return res, nil
}

// countSkip files a non-ready reason under its own counter.
func (r *IngestResult) countSkip(reason string) {
	switch reason {
	case IngestReasonNoRegistry:
		r.SkippedNoRegistry++
	case IngestReasonRegistryDisabled:
		r.SkippedRegistryDisabled++
	case IngestReasonPatternExcluded:
		r.SkippedPatternExcluded++
	case IngestReasonUnparseableRef:
		r.SkippedUnparseableRef++
	}
}
