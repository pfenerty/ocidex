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
	cid, err := parseUUID(clusterID)
	if err != nil {
		return nil, ErrNotFound
	}
	// The cluster read is what enforces visibility on the namespace lookup
	// below: without it, an unauthorized caller could learn a namespace's
	// registry names through this endpoint.
	cluster, err := s.Get(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListClusterUnknownImages(ctx, repository.ListClusterUnknownImagesParams{
		ClusterID: cid,
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
		Limit:     pgtype.Int4{Int32: limit, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("listing unknown cluster images: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	nsID, err := parseUUID(cluster.NamespaceID)
	if err != nil {
		return nil, ErrNotFound
	}
	regRows, err := s.repo.ListRegistriesByNamespace(ctx, nsID)
	if err != nil {
		return nil, fmt.Errorf("listing namespace registries: %w", err)
	}
	registries := make([]Registry, len(regRows))
	for i, r := range regRows {
		registries[i] = fromRepo(registryComposite{
			reg: r.Registry, name: r.Name, ownerID: r.OwnerID, visibility: r.Visibility,
		})
	}

	out := make([]UnknownImage, len(rows))
	for i, r := range rows {
		host, repo := SplitImageRef(r.ImageRef)
		img := UnknownImage{
			ImageRef:           r.ImageRef,
			ImageDigest:        r.ImageDigest,
			RegistryHost:       host,
			Repository:         repo,
			WorkloadCount:      r.WorkloadCount,
			PodCount:           r.PodCount,
			SampleK8sNamespace: r.SampleK8sNamespace,
			SampleWorkloadName: r.SampleWorkloadName,
		}
		resolveIngestTarget(&img, registries)
		out[i] = img
	}
	return out, nil
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
