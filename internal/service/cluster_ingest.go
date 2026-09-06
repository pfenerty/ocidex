package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

// UnknownHost is one registry the gap points at, rolled up.
//
// The gap is a list of images, but the remedy is a registry, and one registry
// closes every row behind it at once. Without this rollup a reader looking at
// twelve ghcr.io rows sees twelve identical "add a registry" links and has to
// work out for themselves that they are one action.
//
// The group is a Scope, not a Host: on a multi-tenant host the credentials stop
// working below the hostname, so ghcr.io/orgA and ghcr.io/orgB are two
// registries and one row covering both would propose a registry that can
// authenticate to half of it. Host remains the registry address — it is what
// fills the form's URL — while Scope is what the row is named after and what
// the created registry is named.
//
// Repositories is what a registry would have to cover to close this gap. It is
// capped, and RepositoryCount always carries the true distinct total, so a
// truncated list can never be read as a complete one (ADR-044 K5).
type UnknownHost struct {
	Host          string
	Scope         string // Host, plus the path segments that belong to the registry
	Reason        string // the worst reason seen for this scope
	ImageCount    int64
	PodCount      int64
	WorkloadCount int64

	Repositories    []string
	RepositoryCount int64

	// Set whenever a registry was matched for this host at all — which is
	// every reason but NoRegistry. Naming it is what makes "switched off" and
	// "excludes this repository" actionable.
	RegistryID   *string
	RegistryName *string
}

// maxHostRepositories caps the repository list carried per host. Chosen to be
// far above any real cluster's per-host repository count while still bounding
// the response and the deep link the UI builds from it.
const maxHostRepositories = 100

// hostRemedyRank orders the reasons that name a registry to configure, worst
// first. A host whose images hit several reasons is reported by the worst one:
// adding a registry subsumes enabling one, which subsumes widening its
// patterns, and reporting the mildest would understate the work.
//
// Ready and UnparseableRef are absent deliberately — neither names a registry
// anyone can go and configure, so neither belongs in this rollup.
var hostRemedyRank = map[string]int{
	IngestReasonNoRegistry:       3,
	IngestReasonRegistryDisabled: 2,
	IngestReasonPatternExcluded:  1,
}

// singleTenantHosts are hosts that would otherwise be split by a rule below but
// must not be: one project or account serving everyone, usually anonymously.
// k8s.gcr.io is the reason this map exists — it ends in .gcr.io but is not a
// multi-tenant registry, and splitting it would turn one public registry into a
// row per Kubernetes subproject.
var singleTenantHosts = map[string]struct{}{
	"registry.k8s.io":   {},
	"k8s.gcr.io":        {},
	"mcr.microsoft.com": {},
}

// multiTenantHosts are hosts whose first repository segment is an account or
// organisation — a different owner, a different credential, a different
// registry.
var multiTenantHosts = map[string]struct{}{
	"ghcr.io":              {},
	"quay.io":              {},
	"docker.io":            {},
	"index.docker.io":      {},
	"registry-1.docker.io": {},
	"gcr.io":               {},
	// Anonymous to pull, but the alias is still an account: two aliases are two
	// owners, and a registry pinned to one has no business listing the other.
	"public.ecr.aws": {},
}

// registryTenancyDepth is how many leading repository path segments belong to
// the registry rather than to the image, for a given host.
//
// This is the "how deep" judgement the rollup turns on, and it is deliberately a
// table of known hosts rather than something inferred from the data. Inferring
// it — splitting any host that shows two distinct first segments — would break
// exactly the case the table's default protects: a self-hosted registry with a
// repository per team is one registry with one credential, and splitting it
// would propose several registries each pinned to an explicit repository list,
// silently giving up catalog discovery.
//
// So an unknown host stays whole. Under-splitting proposes one registry where
// two were needed, which the reader sees and fixes; over-splitting proposes
// registries that each work, and quietly stops finding new repositories.
func registryTenancyDepth(host string) int {
	if _, single := singleTenantHosts[host]; single {
		return 0
	}
	if _, multi := multiTenantHosts[host]; multi {
		return 1
	}
	switch {
	// Google Artifact Registry: LOCATION-docker.pkg.dev/PROJECT/REPOSITORY.
	// The repository, not the project, is what an IAM role is granted on.
	case strings.HasSuffix(host, "-docker.pkg.dev"):
		return 2
	// Regional Container Registry mirrors — us.gcr.io, eu.gcr.io, asia.gcr.io.
	// Reached only after the single-tenant check above has taken k8s.gcr.io.
	case strings.HasSuffix(host, ".gcr.io"):
		return 1
	// Everything else, including ECR (<account>.dkr.ecr.<region>.amazonaws.com)
	// and ACR (<name>.azurecr.io), whose hostnames already name the registry:
	// there is no tenancy boundary left below them to split on.
	default:
		return 0
	}
}

// registryScope is the group key: the host plus the path segments that belong to
// the registry rather than the image.
//
// The prefix may never swallow the whole repository. `ghcr.io/pause` would
// otherwise scope to itself, making a group per image, each proposing a registry
// that serves one thing — so at least one segment always stays behind as the
// image, and a repository too short for its host's depth falls back to what fits.
func registryScope(host, repository string) string {
	depth := registryTenancyDepth(host)
	if depth == 0 || repository == "" {
		return host
	}
	segments := strings.Split(repository, "/")
	if depth > len(segments)-1 {
		depth = len(segments) - 1
	}
	if depth <= 0 {
		return host
	}
	return host + "/" + strings.Join(segments[:depth], "/")
}

// UnknownImagesPage is a page of the No-SBOM gap plus the totals that make the
// page honest: how many images the gap holds, how many of them each remedy
// applies to, and which registries would close it.
//
// Reasons and Hosts cover the whole gap, never the page. A reader who is shown
// twenty rows of "no registry" out of a gap of four hundred needs to know
// whether adding that registry closes the gap or a twentieth of it (ADR-044 K5).
type UnknownImagesPage struct {
	Images  PagedResult[UnknownImage]
	Reasons map[string]int64
	Hosts   []UnknownHost
}

// rollUpHosts groups the gap by the registry its images would be served from,
// keeping only the groups a registry could be configured for.
//
// The key is registryScope, not the bare host: see UnknownHost.
//
// It folds the whole gap rather than the page: the point of the rollup is to
// say how much one registry would fix, and a count taken off fifty rows would
// understate every cluster with more than fifty gapped images.
func rollUpHosts(all []UnknownImage) []UnknownHost {
	type acc struct {
		host  *UnknownHost
		repos map[string]struct{}
		// Collected separately from the set so the cap below trims a sorted
		// list rather than whatever order the map happened to yield.
		reposOrdered []string
	}
	byScope := make(map[string]*acc)
	order := make([]string, 0, 8)

	for _, img := range all {
		if _, wanted := hostRemedyRank[img.Reason]; !wanted {
			continue
		}
		scope := registryScope(img.RegistryHost, img.Repository)
		entry, seen := byScope[scope]
		if !seen {
			entry = &acc{
				host:  &UnknownHost{Host: img.RegistryHost, Scope: scope},
				repos: map[string]struct{}{},
			}
			byScope[scope] = entry
			order = append(order, scope)
		}
		h := entry.host
		h.ImageCount++
		h.PodCount += img.PodCount
		h.WorkloadCount += img.WorkloadCount
		if hostRemedyRank[img.Reason] > hostRemedyRank[h.Reason] {
			h.Reason = img.Reason
		}
		// The first registry seen wins, matching setRegistry: a host can match
		// several registries, and the one named must not flip between reads.
		if h.RegistryID == nil && img.RegistryID != nil {
			h.RegistryID, h.RegistryName = img.RegistryID, img.RegistryName
		}
		if img.Repository != "" {
			if _, dup := entry.repos[img.Repository]; !dup {
				entry.repos[img.Repository] = struct{}{}
				entry.reposOrdered = append(entry.reposOrdered, img.Repository)
			}
		}
	}

	out := make([]UnknownHost, 0, len(order))
	for _, scope := range order {
		entry := byScope[scope]
		h := *entry.host
		h.RepositoryCount = int64(len(entry.reposOrdered))
		repos := entry.reposOrdered
		sort.Strings(repos)
		if len(repos) > maxHostRepositories {
			repos = repos[:maxHostRepositories]
		}
		h.Repositories = repos
		out = append(out, h)
	}

	// Biggest gap first — that is the registry worth configuring next. Scope
	// breaks the tie so the order is stable across reads of the same gap, and
	// so two groups sharing a host never tie with each other.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ImageCount != out[j].ImageCount {
			return out[i].ImageCount > out[j].ImageCount
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

// UnknownImages lists the cluster's No-SBOM gap, each image resolved against
// the registries of the cluster's own namespace.
//
// Resolution is deliberately namespace-local. A registry in another namespace
// could well serve the host, but using it would let one namespace's cluster
// trigger pulls with another namespace's credentials.
//
// The gap is resolved whole and sliced here rather than paged in SQL: whether
// an image is ingestable is decided in Go, so the reason tally has no SQL form,
// and ingest already reads the gap whole on every run.
func (s *clusterService) UnknownImages(ctx context.Context, clusterID string, limit, offset int32, filter VisibilityFilter) (UnknownImagesPage, error) {
	all, _, err := s.resolveUnknownImages(ctx, clusterID, filter)
	if err != nil {
		return UnknownImagesPage{}, err
	}
	reasons := make(map[string]int64, 5)
	for _, img := range all {
		reasons[img.Reason]++
	}
	return UnknownImagesPage{
		Images: PagedResult[UnknownImage]{
			Data:   pageOf(all, limit, offset),
			Total:  int64(len(all)),
			Limit:  limit,
			Offset: offset,
		},
		Reasons: reasons,
		Hosts:   rollUpHosts(all),
	}, nil
}

// pageOf slices one page out of an already-materialized list. An offset past
// the end yields no rows rather than an error: the total travels with the page,
// so a client that has paged off the end can see that it has.
func pageOf[T any](all []T, limit, offset int32) []T {
	if offset < 0 || int(offset) >= len(all) {
		return nil
	}
	end := len(all)
	if limit > 0 && int(offset)+int(limit) < end {
		end = int(offset) + int(limit)
	}
	return all[offset:end]
}

// resolveUnknownImages does the work behind both UnknownImages and
// IngestUnknown, and additionally returns the registries it resolved against
// keyed by id. Ingest needs the whole Registry — URL, credentials, insecure
// flag — where the listing needs only its name; running one resolver for both
// is what keeps the gap list's promise and the ingest attempt from drifting.
func (s *clusterService) resolveUnknownImages(ctx context.Context, clusterID string, filter VisibilityFilter) ([]UnknownImage, map[string]Registry, error) {
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
	images, registries, err := s.resolveUnknownImages(ctx, clusterID, filter)
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
