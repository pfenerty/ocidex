package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// Submitter accepts scan requests.
type Submitter interface {
	Submit(ctx context.Context, req ScanRequest) error
}

// DigestLister returns known SBOM digests for a registry, used to skip re-scanning.
type DigestLister interface {
	ListDigestsBySource(ctx context.Context, sourceID string) (map[string]bool, error)
}

// RegistryWalker performs a catalog walk for a single registry.
// DirectWalker executes the walk in-process; NATSCatalogPublisher delegates to the scanner-worker.
type RegistryWalker interface {
	Walk(ctx context.Context, reg service.Registry) (int, error)
}

// DirectWalker walks a registry catalog in-process and submits scan requests immediately,
// as an alternative to NATSCatalogPublisher when a walk should not be delegated to a worker.
type DirectWalker struct {
	submitter    Submitter
	digestLister DigestLister
	logger       *slog.Logger
}

// NewDirectWalker constructs a DirectWalker.
func NewDirectWalker(sub Submitter, dl DigestLister, logger *slog.Logger) *DirectWalker {
	return &DirectWalker{submitter: sub, digestLister: dl, logger: logger}
}

// Walk fetches known digests then runs WalkRegistry in the calling goroutine.
func (w *DirectWalker) Walk(ctx context.Context, reg service.Registry) (int, error) {
	known := FetchKnownDigests(ctx, w.digestLister, reg.ID)
	return WalkRegistry(ctx, reg, w.submitter, known, w.logger)
}

// FetchKnownDigests loads existing SBOM digests for a registry using a DigestLister.
// Returns nil (not an empty map) if the lister is nil or the registry has no ID.
func FetchKnownDigests(ctx context.Context, dl DigestLister, registryID string) map[string]bool {
	if dl == nil || registryID == "" {
		return nil
	}
	digests, err := dl.ListDigestsBySource(ctx, registryID)
	if err != nil {
		return nil
	}
	return digests
}

// WalkRegistry enumerates a registry catalog, applies filter patterns, and submits
// a ScanRequest for each matching image. Returns the count queued.
// knownDigests contains digests already ingested for this registry; these are
// skipped to avoid re-scanning. Pass nil when unknown.
func WalkRegistry(ctx context.Context, reg service.Registry, sub Submitter, knownDigests map[string]bool, logger *slog.Logger) (int, error) {
	scheme, host := registrySchemeHost(reg)
	baseURL := scheme + "://" + host
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: newOCITokenTransport(derefStr(reg.AuthUsername), derefStr(reg.AuthToken)),
	}

	var repos []string
	if len(reg.Repositories) > 0 {
		repos = reg.Repositories
	} else {
		var err error
		repos, err = ociListCatalog(ctx, client, baseURL)
		if err != nil {
			return 0, fmt.Errorf("listing catalog: %w", err)
		}
		if len(repos) == 0 {
			logger.Warn("catalog returned 0 repositories; if this registry does not support /v2/_catalog, set explicit repositories on the registry config", "registry", reg.Name)
		}
	}

	queued := 0
	for _, repo := range repos {
		if !reg.MatchesRepository(repo) {
			continue
		}
		queued += walkRepo(ctx, client, baseURL, repo, reg, sub, knownDigests, logger)
	}
	return queued, nil
}

// walkRepo scans a single repository: enumerates tagged manifests, then
// optionally discovers untagged manifests via registry-specific APIs.
func walkRepo(ctx context.Context, client *http.Client, baseURL, repo string, reg service.Registry, sub Submitter, knownDigests map[string]bool, logger *slog.Logger) int {
	scannedDigests := make(map[string]bool)
	for d := range knownDigests {
		scannedDigests[d] = true
	}
	queued := 0
	tags, err := ociListTags(ctx, client, baseURL, repo)
	if err != nil {
		logger.Warn("listing tags for repo", "repo", repo, "err", err)
		return 0
	}
	for _, tag := range tags {
		if !reg.MatchesTag(tag) {
			continue
		}
		// Short-circuit before the manifest HEAD/GET. ociGetImageMetadata also
		// catches these by media type, but only after 2-3 registry requests.
		if IsAttachedArtifactTag(tag) {
			logger.Debug("skipping attached artifact", "repo", repo, "tag", tag, "reason", "cosign tag scheme")
			continue
		}
		queued += scanTag(ctx, client, baseURL, repo, tag, reg, sub, scannedDigests, logger)
	}
	if reg.IncludeUntagged {
		queued += discoverUntagged(ctx, client, baseURL, repo, reg, sub, scannedDigests, logger)
	}
	return queued
}

// scanTag resolves a single tag to one or more scan requests.
func scanTag(ctx context.Context, client *http.Client, baseURL, repo, tag string, reg service.Registry, sub Submitter, scannedDigests map[string]bool, logger *slog.Logger) int {
	info, err := ociHeadManifest(ctx, client, baseURL, repo, tag)
	if err != nil {
		logger.Warn("manifest HEAD failed", "repo", repo, "tag", tag, "err", err)
		return 0
	}
	if info.digest == "" {
		logger.Warn("manifest HEAD returned no digest", "repo", repo, "tag", tag)
		return 0
	}
	if scannedDigests[info.digest] {
		return 0
	}
	scannedDigests[info.digest] = true
	if isIndexMediaType(info.mediaType) {
		return scanIndex(ctx, client, baseURL, repo, tag, info.digest, reg, sub, scannedDigests, logger)
	}
	if !isImageManifestType(info.mediaType) {
		logger.Debug("skipping unsupported manifest type", "repo", repo, "tag", tag, "mediaType", info.mediaType)
		return 0
	}
	meta := ociGetImageMetadata(ctx, client, baseURL, repo, info.digest)
	if meta.attachedArtifact {
		logger.Debug("skipping attached artifact", "repo", repo, "tag", tag, "digest", info.digest, "reason", "signature/attestation media type")
		return 0
	}
	if err := sub.Submit(ctx, ScanRequest{
		RegistryURL:  reg.URL,
		Insecure:     reg.Insecure,
		Repository:   repo,
		Digest:       info.digest,
		Tag:          tag,
		Architecture: meta.architecture,
		BuildDate:    meta.buildDate,
		ImageVersion: meta.imageVersion,
		AuthUsername: derefStr(reg.AuthUsername),
		AuthToken:    derefStr(reg.AuthToken),
		RegistryID:   reg.ID,
	}); err != nil {
		logger.Warn("scan submit failed", "repo", repo, "digest", info.digest, "err", err)
		return 0
	}
	return 1
}

// scanIndex expands a multi-arch image index and submits one request per platform.
func scanIndex(ctx context.Context, client *http.Client, baseURL, repo, tag, indexDigest string, reg service.Registry, sub Submitter, scannedDigests map[string]bool, logger *slog.Logger) int {
	platforms, err := ociExpandIndex(ctx, client, baseURL, repo, indexDigest)
	if err != nil {
		logger.Warn("expanding image index", "repo", repo, "tag", tag, "err", err)
		return 0
	}
	queued := 0
	for _, p := range platforms {
		if scannedDigests[p.digest] {
			continue
		}
		scannedDigests[p.digest] = true
		meta := ociGetImageMetadata(ctx, client, baseURL, repo, p.digest)
		if meta.attachedArtifact {
			logger.Debug("skipping attached artifact", "repo", repo, "tag", tag, "digest", p.digest, "reason", "signature/attestation media type")
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

// discoverUntagged uses a registry-type-specific discoverer to find and submit
// manifests not already covered by tag-based scanning.
func discoverUntagged(ctx context.Context, client *http.Client, baseURL, repo string, reg service.Registry, sub Submitter, scannedDigests map[string]bool, logger *slog.Logger) int {
	disc := discovererForType(reg)
	manifests, err := disc.DiscoverManifests(ctx, client, baseURL, repo)
	if err != nil {
		logger.Warn("discovering untagged manifests", "repo", repo, "err", err)
		return 0
	}

	queued := 0
	for _, m := range manifests {
		if scannedDigests[m.Digest] {
			continue
		}
		if !isImageManifestType(m.MediaType) {
			continue
		}
		// The zot and harbor discoverers surface cosign tags, and the ghcr one
		// hardcodes mediaTypeOCIManifest, so the media type above never rejects them.
		if IsAttachedArtifactTag(m.Tag) {
			logger.Debug("skipping attached artifact", "repo", repo, "tag", m.Tag, "reason", "cosign tag scheme")
			continue
		}
		scannedDigests[m.Digest] = true

		if isIndexMediaType(m.MediaType) {
			queued += submitUntaggedIndex(ctx, client, baseURL, repo, m.Digest, reg, sub, scannedDigests, logger)
			continue
		}

		meta := ociGetImageMetadata(ctx, client, baseURL, repo, m.Digest)
		if meta.attachedArtifact {
			logger.Debug("skipping attached artifact", "repo", repo, "digest", m.Digest, "reason", "signature/attestation media type")
			continue
		}
		arch := m.Arch
		if arch == "" {
			arch = meta.architecture
		}
		if err := sub.Submit(ctx, ScanRequest{
			RegistryURL:  reg.URL,
			Insecure:     reg.Insecure,
			Repository:   repo,
			Digest:       m.Digest,
			Architecture: arch,
			BuildDate:    meta.buildDate,
			ImageVersion: meta.imageVersion,
			AuthUsername: derefStr(reg.AuthUsername),
			AuthToken:    derefStr(reg.AuthToken),
			RegistryID:   reg.ID,
		}); err != nil {
			logger.Warn("scan submit failed", "repo", repo, "digest", m.Digest, "err", err)
			continue
		}
		queued++
	}
	return queued
}

// submitUntaggedIndex expands an untagged image index discovered by a
// registry-specific discoverer and submits one request per platform manifest.
func submitUntaggedIndex(ctx context.Context, client *http.Client, baseURL, repo, indexDigest string, reg service.Registry, sub Submitter, scannedDigests map[string]bool, logger *slog.Logger) int {
	platforms, err := ociExpandIndex(ctx, client, baseURL, repo, indexDigest)
	if err != nil {
		logger.Warn("expanding untagged index", "repo", repo, "digest", indexDigest, "err", err)
		return 0
	}
	queued := 0
	for _, p := range platforms {
		if scannedDigests[p.digest] {
			continue
		}
		scannedDigests[p.digest] = true
		meta := ociGetImageMetadata(ctx, client, baseURL, repo, p.digest)
		if meta.attachedArtifact {
			logger.Debug("skipping attached artifact", "repo", repo, "digest", p.digest, "reason", "signature/attestation media type")
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

// normalizeRegistryHost maps known Docker Hub alias hostnames to the canonical
// OCI registry API endpoint. docker.io, index.docker.io, and hub.docker.com all
// redirect to the web frontend; registry-1.docker.io is the actual API.
// It also strips any scheme prefix (e.g. "https://quay.io" → "quay.io") so
// callers that store full URLs in the registry config still work.
//
// The rule lives in internal/service because cluster ingest matches a running
// image's host against a registry's configured URL, and two copies of this
// mapping would eventually disagree about whether they name the same registry.
func normalizeRegistryHost(host string) string {
	return service.NormalizeRegistryHost(host)
}

// decodeJSONBody reads the response body and JSON-decodes it into v.
// If Content-Type is HTML (a sign the URL hit a web frontend instead of the
// registry API), returns a diagnostic error with a body preview without
// attempting to decode. All other content types attempt JSON decode; failures
// include a body preview.
func decodeJSONBody(resp *http.Response, v any) error {
	body, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "html") {
		return fmt.Errorf("registry returned HTML (content-type: %q) — verify the registry URL points to the OCI API endpoint; body: %.200s", ct, body)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w; body: %.200s", err, body)
	}
	return nil
}

// registrySchemeHost returns the scheme and host extracted from reg.URL,
// defaulting to http for insecure registries when no scheme is present.
func registrySchemeHost(reg service.Registry) (scheme, host string) {
	raw := reg.URL
	if i := strings.Index(raw, "://"); i != -1 {
		return raw[:i], normalizeRegistryHost(strings.TrimSuffix(raw[i+3:], "/"))
	}
	host = normalizeRegistryHost(strings.TrimSuffix(raw, "/"))
	if reg.Insecure {
		return schemeHTTP, host
	}
	return schemeHTTPS, host
}

type manifestInfo struct {
	digest    string
	mediaType string
}

// ociListCatalog returns every repository the registry advertises, following
// pagination the same way ociListTags does.
func ociListCatalog(ctx context.Context, c *http.Client, baseURL string) ([]string, error) {
	start := fmt.Sprintf("%s/v2/_catalog?n=%d", baseURL, listPageSize)
	return ociListPaged(ctx, c, baseURL, start, "catalog",
		func(p ociListPage) []string { return p.Repositories })
}

// ociListTags returns every tag in repo. Registries return tags oldest-first and
// page them (ghcr.io and quay.io both do), so reading only the first page hides
// every recent tag on any long-lived repository (ocidex-zogv).
func ociListTags(ctx context.Context, c *http.Client, baseURL, repo string) ([]string, error) {
	start := fmt.Sprintf("%s/v2/%s/tags/list?n=%d", baseURL, repo, listPageSize)
	return ociListPaged(ctx, c, baseURL, start, "tags/list",
		func(p ociListPage) []string { return p.Tags })
}

const (
	// listPageSize is requested on the first page. ghcr.io honours it up to 1000;
	// quay.io ignores it and caps pages at 100 either way.
	listPageSize = 1000
	// maxTagPages bounds the walk so a registry that keeps advertising a next
	// page cannot loop forever.
	maxTagPages = 50
)

// ociListPage holds the response bodies of both paginated list endpoints.
type ociListPage struct {
	Tags         []string `json:"tags"`
	Repositories []string `json:"repositories"`
}

// ociListPaged walks a paginated OCI Distribution list endpoint, following the
// "Link: <...>; rel=next" header until it is absent or maxTagPages is reached,
// accumulating the items selected by items. label names the endpoint in errors.
func ociListPaged(ctx context.Context, c *http.Client, baseURL, startURL, label string,
	items func(ociListPage) []string) ([]string, error) {
	var out []string
	next := startURL
	for page := 0; page < maxTagPages && next != ""; page++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		resp, err := c.Do(req) //nolint:gosec
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("%s returned HTTP %d", label, resp.StatusCode)
		}
		var result ociListPage
		err = decodeJSONBody(resp, &result)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, items(result)...)
		next = nextTagPageURL(baseURL, link)
	}
	return out, nil
}

// nextTagPageURL extracts the rel="next" target from a Link header and resolves
// it against baseURL. Registries return a path-relative URL. Returns "" when the
// header is absent or carries no next relation.
func nextTagPageURL(baseURL, link string) string {
	for _, part := range strings.Split(link, ",") {
		lt := strings.Index(part, "<")
		gt := strings.Index(part, ">")
		if lt == -1 || gt < lt || !strings.Contains(part[gt:], "rel=") {
			continue
		}
		if !strings.Contains(part[gt:], "next") {
			continue
		}
		target := part[lt+1 : gt]
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return target
		}
		return baseURL + target
	}
	return ""
}

// platformEntry holds the digest and architecture for a single platform manifest.
type platformEntry struct {
	digest string
	arch   string
}

// ociExpandIndex fetches an OCI image index or Docker manifest list and returns
// the platform-specific manifests (skips attestations with os="unknown" or empty).
func ociExpandIndex(ctx context.Context, c *http.Client, baseURL, repo, indexDigest string) ([]platformEntry, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/manifests/"+indexDigest, nil)
	req.Header.Set("Accept", strings.Join([]string{
		mediaTypeOCIIndex,
		mediaTypeDockerList,
	}, ","))
	resp, err := c.Do(req) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("index GET returned HTTP %d", resp.StatusCode)
	}
	var index struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
		return nil, fmt.Errorf("decoding index: %w", err)
	}
	entries := make([]platformEntry, 0, len(index.Manifests))
	for _, m := range index.Manifests {
		if m.Digest == "" || m.Platform.OS == "" || m.Platform.OS == "unknown" {
			continue
		}
		entries = append(entries, platformEntry{digest: m.Digest, arch: m.Platform.Arch})
	}
	return entries, nil
}

// imageMetadata holds the architecture, build date, and version resolved from a manifest + config blob.
type imageMetadata struct {
	architecture string
	buildDate    string
	imageVersion string
	// attachedArtifact is true only when the manifest positively identifies as a
	// cosign signature, attestation, or sigstore bundle. It is never set as an
	// error default — ociGetImageMetadata returns the zero value on any failure,
	// so a false here means "image, or undetermined", not "confirmed image".
	attachedArtifact bool
}

// ociManifest is the subset of an OCI/Docker image manifest the catalog walk reads.
type ociManifest struct {
	ArtifactType string `json:"artifactType"`
	Config       struct {
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
	} `json:"layers"`
	Annotations map[string]string `json:"annotations"`
}

// isAttachedArtifact reports whether the manifest describes a cosign signature,
// attestation, or sigstore bundle attached to an image rather than an image itself.
func (m ociManifest) isAttachedArtifact() bool {
	if isAttachedArtifactType(m.ArtifactType) || isAttachedArtifactType(m.Config.MediaType) {
		return true
	}
	for _, l := range m.Layers {
		if isAttachedArtifactType(l.MediaType) {
			return true
		}
	}
	return false
}

// ociGetImageMetadata fetches a manifest and its config blob to extract
// architecture and build date. Returns zero value on any error.
func ociGetImageMetadata(ctx context.Context, c *http.Client, baseURL, repo, digest string) imageMetadata {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/manifests/"+digest, nil)
	req.Header.Set("Accept", strings.Join([]string{
		mediaTypeOCIManifest,
		mediaTypeDockerManifest,
	}, ","))
	resp, err := c.Do(req) //nolint:gosec
	if err != nil {
		return imageMetadata{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return imageMetadata{}
	}
	var manifest ociManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return imageMetadata{}
	}

	// Cosign signatures and attestations are ordinary image manifests; only the
	// artifactType, config media type, or layer media types give them away.
	// Return before fetching the config blob — the caller will not scan this.
	if manifest.isAttachedArtifact() {
		return imageMetadata{attachedArtifact: true}
	}

	annotationVersion := manifest.Annotations["org.opencontainers.image.version"]
	annotationCreated := manifest.Annotations["org.opencontainers.image.created"]

	if manifest.Config.Digest == "" {
		return imageMetadata{
			buildDate:    annotationCreated,
			imageVersion: annotationVersion,
		}
	}
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/blobs/"+manifest.Config.Digest, nil)
	resp2, err := c.Do(req2) //nolint:gosec
	if err != nil {
		return imageMetadata{buildDate: annotationCreated, imageVersion: annotationVersion}
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return imageMetadata{buildDate: annotationCreated, imageVersion: annotationVersion}
	}
	var config struct {
		Architecture string `json:"architecture"`
		Created      string `json:"created"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&config); err != nil {
		return imageMetadata{buildDate: annotationCreated, imageVersion: annotationVersion}
	}

	// architecture: config blob field is authoritative; label is fallback.
	meta := imageMetadata{architecture: config.Architecture}
	if meta.architecture == "" {
		meta.architecture = config.Config.Labels["org.opencontainers.image.architecture"]
	}

	// build_date: config.Created > manifest annotation > config labels.
	switch {
	case config.Created != "":
		meta.buildDate = config.Created
	case annotationCreated != "":
		meta.buildDate = annotationCreated
	case config.Config.Labels["org.opencontainers.image.created"] != "":
		meta.buildDate = config.Config.Labels["org.opencontainers.image.created"]
	default:
		meta.buildDate = config.Config.Labels["org.label-schema.build-date"]
	}
	// image_version: manifest annotation > config labels.
	switch {
	case annotationVersion != "":
		meta.imageVersion = annotationVersion
	case config.Config.Labels["org.opencontainers.image.version"] != "":
		meta.imageVersion = config.Config.Labels["org.opencontainers.image.version"]
	default:
		meta.imageVersion = config.Config.Labels["org.label-schema.version"]
	}
	return meta
}

func ociHeadManifest(ctx context.Context, c *http.Client, baseURL, repo, tag string) (manifestInfo, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, baseURL+"/v2/"+repo+"/manifests/"+tag, nil)
	req.Header.Set("Accept", strings.Join([]string{
		mediaTypeOCIManifest,
		mediaTypeDockerManifest,
		mediaTypeOCIIndex,
		mediaTypeDockerList,
	}, ","))
	resp, err := c.Do(req) //nolint:gosec
	if err != nil {
		return manifestInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return manifestInfo{}, fmt.Errorf("manifest HEAD returned HTTP %d", resp.StatusCode)
	}
	return manifestInfo{
		digest:    resp.Header.Get("Docker-Content-Digest"),
		mediaType: strings.Split(resp.Header.Get("Content-Type"), ";")[0],
	}, nil
}

func isIndexMediaType(mt string) bool {
	return mt == mediaTypeOCIIndex ||
		mt == mediaTypeDockerList
}

// ociTokenTransport implements OCI Distribution Spec token authentication.
// On 401, it parses the Www-Authenticate challenge. For Bearer challenges it
// exchanges credentials for a scoped token (cached by "host|scope") and retries.
// For Basic challenges it retries with HTTP Basic auth credentials.
type ociTokenTransport struct {
	base     http.RoundTripper
	username string // empty = anonymous
	password string // PAT or password
	mu       sync.Mutex
	tokens   map[string]string // "host|scope" -> bearer token
}

func newOCITokenTransport(username, password string) *ociTokenTransport {
	return &ociTokenTransport{
		base:     http.DefaultTransport,
		username: username,
		password: password,
		tokens:   make(map[string]string),
	}
}

func (t *ociTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	challenge := resp.Header.Get("Www-Authenticate")

	// Handle Basic auth challenge.
	if strings.HasPrefix(challenge, "Basic ") {
		if t.username == "" || t.password == "" {
			return resp, nil
		}
		resp.Body.Close()
		retry := req.Clone(req.Context())
		if req.GetBody != nil {
			retry.Body, _ = req.GetBody()
		}
		retry.SetBasicAuth(t.username, t.password)
		return t.base.RoundTrip(retry)
	}

	// Handle Bearer token challenge.
	realm, svc, scope := parseWWWAuthenticate(challenge)
	if realm == "" {
		return resp, nil // not a recognized challenge, return as-is
	}

	// Check cache for a token matching this host+scope.
	cacheKey := req.URL.Host + "|" + scope
	t.mu.Lock()
	cachedToken := t.tokens[cacheKey]
	t.mu.Unlock()

	if cachedToken == "" {
		var fetchErr error
		cachedToken, fetchErr = t.fetchToken(req.Context(), realm, svc, scope)
		if fetchErr != nil {
			// Token exchange failed (e.g. ghcr.io returns 403 for unsupported scopes
			// like catalog). Return the original 401 so the caller can handle it
			// rather than surfacing a transport-level error.
			slog.Debug("OCI token exchange failed", "host", req.URL.Host, "scope", scope, "err", fetchErr) //nolint:gosec // G706: host and scope come from the registry's WWW-Authenticate header, not arbitrary user input
			return resp, nil                                                                               //nolint:nilerr // intentional: fall back to original 401 response
		}
		t.mu.Lock()
		t.tokens[cacheKey] = cachedToken
		t.mu.Unlock()
	}

	resp.Body.Close()
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		retry.Body, _ = req.GetBody()
	}
	retry.Header.Set("Authorization", "Bearer "+cachedToken)
	return t.base.RoundTrip(retry)
}

func (t *ociTokenTransport) fetchToken(ctx context.Context, realm, svc, scope string) (string, error) {
	u := realm + "?"
	if svc != "" {
		u += "service=" + svc + "&"
	}
	if scope != "" {
		u += "scope=" + scope
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // G704: URL is from registry's Www-Authenticate header
	if err != nil {
		return "", err
	}
	if t.username != "" && t.password != "" {
		tokenReq.SetBasicAuth(t.username, t.password)
	}

	resp, err := t.base.RoundTrip(tokenReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	// Some registries use "token", others use "access_token".
	if result.Token != "" {
		return result.Token, nil
	}
	return result.AccessToken, nil
}

// parseWWWAuthenticate extracts realm, service, and scope from a
// Www-Authenticate header of the form:
//
//	Bearer realm="...",service="...",scope="..."
func parseWWWAuthenticate(header string) (realm, svc, scope string) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", "", ""
	}
	params := header[len("Bearer "):]
	for _, part := range strings.Split(params, ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"")
		switch k {
		case "realm":
			realm = v
		case "service":
			svc = v
		case "scope":
			scope = v
		}
	}
	return realm, svc, scope
}

// derefStr returns the string value of a *string pointer, or "" if nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
