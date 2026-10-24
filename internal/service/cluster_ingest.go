package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Where an unknown image stands. Every state but ready is reported rather than
// retried, because each has a different remedy and none of them is fixed by
// asking again (ADR-044 K9, K10).
const (
	// IngestReasonReady means the image will be queued on the next run, with a
	// registry's credentials or, when RegistryID is nil, anonymously.
	IngestReasonReady = "ready"
	// IngestReasonScanning means a scan job for it is queued or running.
	IngestReasonScanning = "scanning"
	// IngestReasonUnauthorized means the host refused the pull. The remedy is a
	// registry with credentials for it, then an explicit Ingest of the row.
	IngestReasonUnauthorized = "unauthorized"
	// IngestReasonEgressDenied means the host resolved to an address the
	// egress policy refuses (ocidex-avsz).
	IngestReasonEgressDenied = "egress_denied"
	// IngestReasonFailed means the manifest was not there, or a scan used up
	// its attempts. An explicit Ingest of the row retries it.
	IngestReasonFailed = "failed"
	// IngestReasonDeleted means its SBOM was deleted on purpose (ADR-0053 S6).
	// Cluster ingest never brings it back; a rescan from the SBOM page does.
	IngestReasonDeleted = "deleted"
	// IngestReasonRegistryDisabled means the host matches a registry that is
	// switched off. The remedy is to enable it, not to add another.
	IngestReasonRegistryDisabled = "registry_disabled"
	// IngestReasonUnparseableRef means the reported reference has no host, so
	// there is nothing to resolve against. This overlaps with the K3 gap: a
	// runtime reporting a bare identifier gives no registry to ask.
	IngestReasonUnparseableRef = "unparseable_ref"
)

// IngestRefusalNotFound is the refusal recorded for a manifest the host does not
// have. It reports as IngestReasonFailed: nothing names a remedy for it.
const IngestRefusalNotFound = "not_found"

// IngestRefusedError is a running image's pull that failed for a reason asking
// again will not fix: Reason is IngestReasonUnauthorized,
// IngestReasonEgressDenied or IngestRefusalNotFound. IngestUnknown records it as a failed
// job instead of retrying it every snapshot (ADR-0044 K10).
type IngestRefusedError struct {
	Reason string
	Err    error
}

func (e *IngestRefusedError) Error() string { return e.Reason + ": " + e.Err.Error() }
func (e *IngestRefusedError) Unwrap() error { return e.Err }

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
	// are set whenever a registry was matched at all: the one whose credentials
	// pull the image, or the disabled one that blocks it, which is only
	// actionable named. A nil RegistryID on a ready image
	// means an anonymous pull.
	Reason       string
	RegistryID   *string
	RegistryName *string

	// attribution is the source the SBOM will belong to: the registry when
	// its scope claims the repository, otherwise the cluster (ADR-0044 K10).
	attribution string
	// failedJobs are the failed jobs behind a failed, unauthorized or
	// egress_denied image, which an explicit Ingest drops to retry it.
	failedJobs []pgtype.UUID
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

	// Set whenever a registry was matched for this host. Naming it is what
	// makes "switched off" and "wrong credentials" actionable; an
	// unauthorized host usually has none, and the remedy is to add one.
	RegistryID   *string
	RegistryName *string
}

// maxHostRepositories caps the repository list carried per host. Chosen to be
// far above any real cluster's per-host repository count while still bounding
// the response and the deep link the UI builds from it.
const maxHostRepositories = 100

// hostRemedyRank orders the reasons that name a registry to configure, worst
// first. A host whose images hit several reasons is reported by the worst one:
// adding a registry with credentials subsumes enabling one, and reporting
// the milder would understate the work.
//
// Ready and UnparseableRef are absent deliberately — neither names a registry
// anyone can go and configure, so neither belongs in this rollup.
var hostRemedyRank = map[string]int{
	IngestReasonUnauthorized:     3,
	IngestReasonRegistryDisabled: 2,
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
		reg, err := decryptCredentials(s.box, fromRepo(registryComposite{
			reg: r.Registry, name: r.Name, visibility: r.Visibility,
		}))
		if err != nil {
			return nil, nil, err
		}
		registries[i] = reg
		byID[reg.ID] = reg
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
		resolveIngestTarget(&img, registries, cluster.ID)
		out[i] = img
	}
	if err := s.applyJobStates(ctx, out); err != nil {
		return nil, nil, err
	}
	return out, byID, nil
}

// applyJobStates moves each ready image to the state of the jobs already under
// its attribution: scanning while one is active, the recorded refusal or
// failure when one failed, deleted when its SBOM was pruned on purpose. This
// is what makes a repeat snapshot free (ADR-0044 K10): an image that has a job
// is never sent to its host again. A succeeded job whose SBOM is gone, as
// retention leaves it, does not count; that image is scanned again.
func (s *clusterService) applyJobStates(ctx context.Context, images []UnknownImage) error {
	digests := make([]string, 0, len(images))
	for _, img := range images {
		if img.Reason == IngestReasonReady {
			digests = append(digests, img.ImageDigest)
		}
	}
	if len(digests) == 0 {
		return nil
	}
	jobs, err := s.repo.ListScanJobsForDigests(ctx, digests)
	if err != nil {
		return fmt.Errorf("listing scan jobs for running images: %w", err)
	}
	for i := range images {
		if images[i].Reason == IngestReasonReady {
			images[i].applyJobs(jobs)
		}
	}
	return nil
}

// applyJobs sets the image's state from the jobs under its attribution.
func (u *UnknownImage) applyJobs(jobs []repository.ListScanJobsForDigestsRow) {
	reason := ""
	for _, j := range jobs {
		if jobAttribution(j) != u.attribution ||
			(j.Digest != u.ImageDigest && j.IndexDigest.String != u.ImageDigest) {
			continue
		}
		r := jobStateReason(j)
		if r == IngestReasonUnauthorized || r == IngestReasonEgressDenied || r == IngestReasonFailed {
			u.failedJobs = append(u.failedJobs, j.ID)
		}
		if jobReasonRank[r] > jobReasonRank[reason] {
			reason = r
		}
	}
	if reason != "" {
		u.Reason = reason
	}
}

// jobReasonRank decides an image's state when several jobs sit behind it, as
// the per-platform jobs of an index do: one still scanning outweighs a
// sibling that failed, and any failure outweighs a pruned sibling.
var jobReasonRank = map[string]int{
	IngestReasonDeleted:      1,
	IngestReasonFailed:       2,
	IngestReasonEgressDenied: 3,
	IngestReasonUnauthorized: 4,
	IngestReasonScanning:     5,
}

func jobAttribution(j repository.ListScanJobsForDigestsRow) string {
	if j.ClusterID.Valid {
		return uuidToStr(j.ClusterID)
	}
	return uuidToStr(j.RegistryID)
}

// jobStateReason maps one job to the image state it implies, "" for one that
// implies nothing (succeeded).
func jobStateReason(j repository.ListScanJobsForDigestsRow) string {
	switch ScanJobState(j.State) {
	case ScanJobSucceeded:
		return ""
	case ScanJobQueued, ScanJobRunning:
		return IngestReasonScanning
	case ScanJobPruned:
		return IngestReasonDeleted
	case ScanJobFailed:
		// A refusal is recorded with its reason as the error's prefix.
		for _, r := range []string{IngestReasonUnauthorized, IngestReasonEgressDenied} {
			if strings.HasPrefix(j.LastError.String, r+": ") {
				return r
			}
		}
		return IngestReasonFailed
	}
	return ""
}

// resolveIngestTarget picks the registry whose credentials pull img and the
// source its SBOM is attributed to, or records why it cannot be ingested.
//
// An enabled registry that accepts the repository wins outright, and the SBOM
// is the registry's. Failing that, the first enabled registry for the host
// pulls it with its credentials even though its patterns exclude the
// repository: patterns scope the catalog walk, and a running image is already
// chosen. That SBOM, like one pulled anonymously from a host no registry in
// the namespace matches, is the cluster's (ADR-0044 K10). A host whose only
// match is switched off is not ingested, and the reason names that registry.
func resolveIngestTarget(img *UnknownImage, registries []Registry, clusterID string) {
	if img.RegistryHost == "" {
		img.Reason = IngestReasonUnparseableRef
		return
	}
	var credentials, disabled *Registry
	for i := range registries {
		reg := &registries[i]
		if reg.Host() != img.RegistryHost {
			continue
		}
		switch {
		case !reg.Enabled:
			if disabled == nil {
				disabled = reg
			}
		case reg.ClaimsRepository(img.Repository):
			img.setRegistry(*reg, IngestReasonReady)
			img.attribution = reg.ID
			return
		case credentials == nil:
			credentials = reg
		}
	}
	switch {
	case credentials != nil:
		img.setRegistry(*credentials, IngestReasonReady)
		img.attribution = clusterID
	case disabled != nil:
		img.setRegistry(*disabled, IngestReasonRegistryDisabled)
	default:
		img.Reason, img.attribution = IngestReasonReady, clusterID
	}
}

// setRegistry names the matched registry and the reason.
func (u *UnknownImage) setRegistry(reg Registry, reason string) {
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

// RunningImageTarget is where a running image is pulled from and whose SBOM
// it becomes.
type RunningImageTarget struct {
	// Registry supplies the credentials; nil pulls anonymously from Host.
	Registry *Registry
	// Host is the normalized registry host from the image reference.
	Host string
	// ClusterID attributes the SBOM to that cluster; empty attributes it to
	// Registry (ADR-0044 K10).
	ClusterID string
}

// RunningImageSubmitter turns one running image into scan jobs, returning how
// many it queued. A multi-arch image expands into one job per platform, so the
// count is not always one. A pull the host refuses for good is returned as an
// *IngestRefusedError.
//
// The interface lives in service because internal/scanner imports this package
// and not the other way round; scanner.ClusterIngestor implements it.
type RunningImageSubmitter interface {
	SubmitForRunningImage(ctx context.Context, target RunningImageTarget, repo, digest, tag string) (int, error)
}

// IngestResult accounts for every unknown image an ingest run considered.
//
// Outcomes are counted per reason rather than summed. "Nothing was queued"
// and "nothing could be queued because ghcr.io refused the pull" are the same
// number and different problems, and each reason has its own remedy (ADR-044).
type IngestResult struct {
	// Considered is every unknown image looked at, so the counts below can be
	// read as a complete accounting rather than a sample.
	Considered int
	Queued     int
	// SkippedExisting counts images that already have a job: scanning,
	// failed, or deleted on purpose. A repeat snapshot lands here.
	SkippedExisting         int
	SkippedRegistryDisabled int
	SkippedUnparseableRef   int
	// Unauthorized and EgressDenied count images refused by their host, in
	// this run or a recorded earlier one. Neither is retried.
	Unauthorized int
	EgressDenied int
	// Failed counts images whose submission errored: a manifest that is not
	// there, or a transient registry or queue problem.
	Failed int
}

// IngestUnknownParams narrows an ingest run.
type IngestUnknownParams struct {
	// ImageDigests, when non-empty, limits the run to those images. Empty means
	// the whole gap, which is what the snapshot trigger wants; the per-row
	// button in the UI passes one digest so the button does what it says
	// rather than quietly queueing the cluster. Naming an image is also the
	// retry for its failed jobs.
	ImageDigests []string
}

// IngestUnknown submits a scan job for every running image with no SBOM and no
// job: with a registry's credentials when one in the cluster's namespace serves
// the host, anonymously otherwise (ADR-0044 K10).
//
// Repeat runs are free: an image that already has a job is skipped before any
// network call, and a refusal is recorded as a failed job, so a snapshot that
// reports the same unscanned images again contacts no host. That is what makes
// it safe to fire this on every push.
func (s *clusterService) IngestUnknown(ctx context.Context, clusterID string, sub RunningImageSubmitter, params IngestUnknownParams, filter VisibilityFilter) (IngestResult, error) {
	if sub == nil {
		return IngestResult{}, &ValidationError{Message: "scanning is not enabled on this deployment"}
	}
	images, registries, err := s.resolveUnknownImages(ctx, clusterID, filter)
	if err != nil {
		return IngestResult{}, err
	}

	if len(params.ImageDigests) > 0 {
		images = onlyDigests(images, params.ImageDigests)
		// A human naming a row is its retry: its failed jobs go, and the run
		// asks the host again. A pruned job stays.
		if err := s.dropFailedJobs(ctx, images); err != nil {
			return IngestResult{}, err
		}
	}

	var res IngestResult
	res.Considered = len(images)
	for _, img := range images {
		if !img.Ingestable() {
			res.countSkip(img.Reason)
			continue
		}
		target, ok := img.target(registries)
		if !ok {
			// resolveIngestTarget only names a registry it found, so this
			// cannot happen; count it rather than panicking on a future
			// refactor that makes it possible.
			res.Failed++
			continue
		}
		queued, err := sub.SubmitForRunningImage(ctx, target, img.Repository, img.ImageDigest, img.Tag)
		var refused *IngestRefusedError
		switch {
		case errors.As(err, &refused):
			if err := s.recordRefusal(ctx, target, img, refused); err != nil {
				return res, err
			}
			res.countRefusal(refused.Reason)
		case err != nil:
			// One unreachable registry must not abandon the images served by
			// the others.
			res.Failed++
		default:
			res.Queued += queued
		}
	}
	return res, nil
}

// onlyDigests keeps the images the caller named. Filtering here rather than in
// SQL keeps one resolver for both callers: a digest the caller names but the
// cluster is not running unknown simply matches nothing, which is the right
// answer for a stale button.
func onlyDigests(images []UnknownImage, digests []string) []UnknownImage {
	wanted := make(map[string]bool, len(digests))
	for _, d := range digests {
		wanted[d] = true
	}
	kept := images[:0]
	for _, img := range images {
		if wanted[img.ImageDigest] {
			kept = append(kept, img)
		}
	}
	return kept
}

// target is where a ready image is pulled from and whose SBOM it becomes. The
// bool is false when the registry it names is not among registries.
func (u UnknownImage) target(registries map[string]Registry) (RunningImageTarget, bool) {
	t := RunningImageTarget{Host: u.RegistryHost}
	if u.RegistryID != nil {
		reg, ok := registries[*u.RegistryID]
		if !ok {
			return t, false
		}
		t.Registry = &reg
	}
	if u.attribution != "" && (t.Registry == nil || u.attribution != t.Registry.ID) {
		t.ClusterID = u.attribution
	}
	return t, true
}

// dropFailedJobs deletes the failed jobs behind images, which then count as
// ready again.
func (s *clusterService) dropFailedJobs(ctx context.Context, images []UnknownImage) error {
	var ids []pgtype.UUID
	for i := range images {
		if len(images[i].failedJobs) == 0 {
			continue
		}
		ids = append(ids, images[i].failedJobs...)
		images[i].failedJobs = nil
		images[i].Reason = IngestReasonReady
	}
	if len(ids) == 0 {
		return nil
	}
	if _, err := s.repo.DeleteFailedScanJobs(ctx, ids); err != nil {
		return fmt.Errorf("dropping failed scan jobs: %w", err)
	}
	return nil
}

// recordRefusal writes the failed job that keeps later snapshots from asking
// the host again. Its key is the one a queued job would have had.
func (s *clusterService) recordRefusal(ctx context.Context, target RunningImageTarget, img UnknownImage, refused *IngestRefusedError) error {
	arg := repository.RecordRefusedScanJobParams{
		Repository: img.Repository,
		Digest:     img.ImageDigest,
		Tag:        toNullText(nullStr(img.Tag)),
		NatsMsgID:  pgtype.Text{String: ScanJobKey(img.attribution, img.ImageDigest), Valid: true},
		LastError:  toNullText(nullStr(refused.Error())),
		ClusterID:  optionalUUID(target.ClusterID),
	}
	if target.Registry != nil {
		arg.RegistryID = optionalUUID(target.Registry.ID)
	} else {
		arg.RegistryHost = toNullText(nullStr(target.Host))
	}
	if err := s.repo.RecordRefusedScanJob(ctx, arg); err != nil {
		return fmt.Errorf("recording refused pull: %w", err)
	}
	return nil
}

// countSkip files a non-ready reason under its own counter.
func (r *IngestResult) countSkip(reason string) {
	switch reason {
	case IngestReasonRegistryDisabled:
		r.SkippedRegistryDisabled++
	case IngestReasonUnparseableRef:
		r.SkippedUnparseableRef++
	case IngestReasonUnauthorized, IngestReasonEgressDenied:
		r.countRefusal(reason)
	case IngestReasonScanning, IngestReasonFailed, IngestReasonDeleted:
		r.SkippedExisting++
	}
}

// countRefusal files a host's refusal under its own counter.
func (r *IngestResult) countRefusal(reason string) {
	switch reason {
	case IngestReasonUnauthorized:
		r.Unauthorized++
	case IngestReasonEgressDenied:
		r.EgressDenied++
	default:
		r.Failed++
	}
}
