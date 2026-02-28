package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// ListRegistries returns all configured registries (admin only).
func (h *Handler) ListRegistries(ctx context.Context, _ *struct{}) (*ListRegistriesOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	regs, err := h.registryService.List(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing registries: %v", err))
	}
	out := &ListRegistriesOutput{}
	out.Body.Registries = make([]RegistryResponse, len(regs))
	for i, r := range regs {
		out.Body.Registries[i] = toRegistryResponse(r)
	}
	return out, nil
}

// GetRegistry returns a single registry by ID (admin only).
func (h *Handler) GetRegistry(ctx context.Context, in *GetRegistryInput) (*GetRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &GetRegistryOutput{Body: toRegistryResponse(reg)}, nil
}

// CreateRegistry creates a new registry (admin only).
func (h *Handler) CreateRegistry(ctx context.Context, in *CreateRegistryInput) (*CreateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	reg, err := h.registryService.Create(ctx, in.Body.Name, in.Body.Type, in.Body.URL, in.Body.Insecure, in.Body.WebhookSecret, in.Body.RepositoryPatterns, in.Body.TagPatterns)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("creating registry: %v", err))
	}
	return &CreateRegistryOutput{Body: toRegistryResponse(reg)}, nil
}

// UpdateRegistry updates a registry (admin only).
func (h *Handler) UpdateRegistry(ctx context.Context, in *UpdateRegistryInput) (*UpdateRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	reg, err := h.registryService.Update(ctx, in.ID, in.Body.Name, in.Body.Type, in.Body.URL, in.Body.Insecure, in.Body.WebhookSecret, in.Body.Enabled, in.Body.RepositoryPatterns, in.Body.TagPatterns)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return &UpdateRegistryOutput{Body: toRegistryResponse(reg)}, nil
}

// DeleteRegistry deletes a registry (admin only).
func (h *Handler) DeleteRegistry(ctx context.Context, in *DeleteRegistryInput) (*struct{}, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	if err := h.registryService.Delete(ctx, in.ID); err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	return nil, nil
}

// TestRegistryConnection probes the registry's /v2/ endpoint (admin only).
func (h *Handler) TestRegistryConnection(ctx context.Context, in *TestRegistryConnectionInput) (*TestRegistryConnectionOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}

	scheme := "https"
	if in.Body.Insecure {
		scheme = "http"
	}
	target := fmt.Sprintf("%s://%s/v2/", scheme, in.Body.URL)

	c := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		out := &TestRegistryConnectionOutput{}
		out.Body.Reachable = false
		out.Body.Message = fmt.Sprintf("invalid URL: %v", err)
		return out, nil
	}

	resp, err := c.Do(req)
	out := &TestRegistryConnectionOutput{}
	if err != nil {
		out.Body.Reachable = false
		out.Body.Message = err.Error()
		return out, nil
	}
	defer resp.Body.Close()

	// 200 OK = open registry; 401 Unauthorized = auth required but registry is up.
	out.Body.Reachable = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
	out.Body.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	return out, nil
}

// ScanRegistry triggers an ad-hoc catalog walk of a registry (admin only).
// It runs asynchronously and returns immediately.
func (h *Handler) ScanRegistry(ctx context.Context, in *ScanRegistryInput) (*ScanRegistryOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != "admin" {
		return nil, huma.Error403Forbidden("admin only")
	}
	reg, err := h.registryService.Get(ctx, in.ID)
	if err != nil {
		return nil, huma.Error404NotFound("registry not found")
	}
	if h.scanSubmitter == nil {
		return nil, huma.Error503ServiceUnavailable("scanner not enabled")
	}
	go func() {
		walkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		queued, err := walkRegistryCatalog(walkCtx, reg, h.scanSubmitter)
		if err != nil {
			slog.Error("ad-hoc registry scan failed", "registry", reg.Name, "err", err)
			return
		}
		slog.Info("ad-hoc registry scan complete", "registry", reg.Name, "queued", queued)
	}()
	out := &ScanRegistryOutput{}
	out.Body.Message = fmt.Sprintf("scan started for registry %q", reg.Name)
	return out, nil
}

// walkRegistryCatalog enumerates repositories and tags from the registry,
// applies the registry's filter patterns, resolves digests, and submits
// ScanRequests for each matching single-manifest image. Returns the count queued.
func walkRegistryCatalog(ctx context.Context, reg service.Registry, sub ScanSubmitter) (int, error) {
	scheme, host := registrySchemeHost(reg)
	baseURL := scheme + "://" + host
	client := &http.Client{Timeout: 15 * time.Second}

	repos, err := ociListCatalog(ctx, client, baseURL)
	if err != nil {
		return 0, fmt.Errorf("listing catalog: %w", err)
	}

	queued := 0
	for _, repo := range repos {
		if !reg.MatchesRepository(repo) {
			continue
		}
		tags, err := ociListTags(ctx, client, baseURL, repo)
		if err != nil {
			slog.Warn("listing tags for repo", "repo", repo, "err", err)
			continue
		}
		for _, tag := range tags {
			if !reg.MatchesTag(tag) {
				continue
			}
			info, err := ociHeadManifest(ctx, client, baseURL, repo, tag)
			if err != nil {
				slog.Warn("manifest HEAD failed", "repo", repo, "tag", tag, "err", err)
				continue
			}
			if info.digest == "" {
				slog.Warn("manifest HEAD returned no digest", "repo", repo, "tag", tag)
				continue
			}
			if isIndexMediaType(info.mediaType) {
				// Multi-arch image: expand index to per-platform manifests.
				platforms, err := ociExpandIndex(ctx, client, baseURL, repo, info.digest)
				if err != nil {
					slog.Warn("expanding image index", "repo", repo, "tag", tag, "err", err)
					continue
				}
				for _, p := range platforms {
					meta := ociGetImageMetadata(ctx, client, baseURL, repo, p.digest)
					arch := p.arch // index entry is authoritative for arch
					if arch == "" {
						arch = meta.architecture
					}
					sub.Submit(scanner.ScanRequest{
						RegistryURL:  reg.URL,
						Insecure:     reg.Insecure,
						Repository:   repo,
						Digest:       p.digest,
						Tag:          tag,
						Architecture: arch,
						BuildDate:    meta.buildDate,
					})
					queued++
				}
				continue
			}
			meta := ociGetImageMetadata(ctx, client, baseURL, repo, info.digest)
			sub.Submit(scanner.ScanRequest{
				RegistryURL:  reg.URL,
				Insecure:     reg.Insecure,
				Repository:   repo,
				Digest:       info.digest,
				Tag:          tag,
				Architecture: meta.architecture,
				BuildDate:    meta.buildDate,
			})
			queued++
		}
	}
	return queued, nil
}

// registrySchemeHost returns the scheme and host extracted from reg.URL,
// defaulting to http for insecure registries when no scheme is present.
func registrySchemeHost(reg service.Registry) (scheme, host string) {
	raw := reg.URL
	if i := strings.Index(raw, "://"); i != -1 {
		return raw[:i], strings.TrimSuffix(raw[i+3:], "/")
	}
	host = strings.TrimSuffix(raw, "/")
	if reg.Insecure {
		return "http", host
	}
	return "https", host
}

type manifestInfo struct {
	digest    string
	mediaType string
}

func ociListCatalog(ctx context.Context, c *http.Client, baseURL string) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/_catalog", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Repositories, nil
}

func ociListTags(ctx context.Context, c *http.Client, baseURL, repo string) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/tags/list", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags/list returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Tags, nil
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
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}, ","))
	resp, err := c.Do(req)
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
	var entries []platformEntry
	for _, m := range index.Manifests {
		if m.Digest == "" || m.Platform.OS == "" || m.Platform.OS == "unknown" {
			continue
		}
		entries = append(entries, platformEntry{digest: m.Digest, arch: m.Platform.Arch})
	}
	return entries, nil
}

// imageMetadata holds the architecture and build date resolved from a manifest + config blob.
type imageMetadata struct {
	architecture string // from image config blob
	buildDate    string // from manifest annotations, or image config blob as fallback
}

// ociGetImageMetadata fetches a manifest and its config blob to extract
// architecture and build date. Returns zero value on any error.
func ociGetImageMetadata(ctx context.Context, c *http.Client, baseURL, repo, digest string) imageMetadata {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/manifests/"+digest, nil)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ","))
	resp, err := c.Do(req)
	if err != nil {
		return imageMetadata{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return imageMetadata{}
	}
	var manifest struct {
		Config      struct{ Digest string `json:"digest"` } `json:"config"`
		Annotations map[string]string                      `json:"annotations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return imageMetadata{}
	}
	meta := imageMetadata{
		buildDate: manifest.Annotations["org.opencontainers.image.created"],
	}
	if manifest.Config.Digest == "" {
		return meta
	}
	// Fetch the image config blob for architecture and (if not in annotations) build date.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/blobs/"+manifest.Config.Digest, nil)
	resp2, err := c.Do(req2)
	if err != nil {
		return meta
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return meta
	}
	var config struct {
		Architecture string `json:"architecture"`
		Created      string `json:"created"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&config); err != nil {
		return meta
	}
	meta.architecture = config.Architecture
	if meta.buildDate == "" {
		meta.buildDate = config.Created
	}
	return meta
}

func ociHeadManifest(ctx context.Context, c *http.Client, baseURL, repo, tag string) (manifestInfo, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, baseURL+"/v2/"+repo+"/manifests/"+tag, nil)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}, ","))
	resp, err := c.Do(req)
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
	return mt == "application/vnd.oci.image.index.v1+json" ||
		mt == "application/vnd.docker.distribution.manifest.list.v2+json"
}

func toRegistryResponse(r service.Registry) RegistryResponse {
	rr := RegistryResponse{
		ID:                 r.ID,
		Name:               r.Name,
		Type:               r.Type,
		URL:                r.URL,
		Insecure:           r.Insecure,
		HasSecret:          r.WebhookSecret != nil && *r.WebhookSecret != "",
		Enabled:            r.Enabled,
		WebhookPath:        "/api/v1/webhooks/" + r.ID,
		RepositoryPatterns: r.RepositoryPatterns,
		TagPatterns:        r.TagPatterns,
		CreatedAt:          r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:          r.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if rr.RepositoryPatterns == nil {
		rr.RepositoryPatterns = []string{}
	}
	if rr.TagPatterns == nil {
		rr.TagPatterns = []string{}
	}
	return rr
}
