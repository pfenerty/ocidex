package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// Submitter accepts scan requests.
type Submitter interface {
	Submit(req ScanRequest)
}

// WalkRegistry enumerates a registry catalog, applies filter patterns, and submits
// a ScanRequest for each matching image. Returns the count queued.
func WalkRegistry(ctx context.Context, reg service.Registry, sub Submitter, logger *slog.Logger) (int, error) {
	scheme, host := registrySchemeHost(reg)
	baseURL := scheme + "://" + host
	client := &http.Client{Timeout: 15 * time.Second}

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
		tags, err := ociListTags(ctx, client, baseURL, repo)
		if err != nil {
			logger.Warn("listing tags for repo", "repo", repo, "err", err)
			continue
		}
		for _, tag := range tags {
			if !reg.MatchesTag(tag) {
				continue
			}
			info, err := ociHeadManifest(ctx, client, baseURL, repo, tag)
			if err != nil {
				logger.Warn("manifest HEAD failed", "repo", repo, "tag", tag, "err", err)
				continue
			}
			if info.digest == "" {
				logger.Warn("manifest HEAD returned no digest", "repo", repo, "tag", tag)
				continue
			}
			if isIndexMediaType(info.mediaType) {
				platforms, err := ociExpandIndex(ctx, client, baseURL, repo, info.digest)
				if err != nil {
					logger.Warn("expanding image index", "repo", repo, "tag", tag, "err", err)
					continue
				}
				for _, p := range platforms {
					meta := ociGetImageMetadata(ctx, client, baseURL, repo, p.digest)
					arch := p.arch
					if arch == "" {
						arch = meta.architecture
					}
					sub.Submit(ScanRequest{
						RegistryURL:  reg.URL,
						Insecure:     reg.Insecure,
						Repository:   repo,
						Digest:       p.digest,
						Tag:          tag,
						Architecture: arch,
						BuildDate:    meta.buildDate,
						ImageVersion: meta.imageVersion,
					})
					queued++
				}
				continue
			}
			meta := ociGetImageMetadata(ctx, client, baseURL, repo, info.digest)
			sub.Submit(ScanRequest{
				RegistryURL:  reg.URL,
				Insecure:     reg.Insecure,
				Repository:   repo,
				Digest:       info.digest,
				Tag:          tag,
				Architecture: meta.architecture,
				BuildDate:    meta.buildDate,
				ImageVersion: meta.imageVersion,
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

// imageMetadata holds the architecture, build date, and version resolved from a manifest + config blob.
type imageMetadata struct {
	architecture string
	buildDate    string
	imageVersion string
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
	annotationVersion := manifest.Annotations["org.opencontainers.image.version"]
	annotationCreated := manifest.Annotations["org.opencontainers.image.created"]

	if manifest.Config.Digest == "" {
		return imageMetadata{
			buildDate:    annotationCreated,
			imageVersion: annotationVersion,
		}
	}
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/blobs/"+manifest.Config.Digest, nil)
	resp2, err := c.Do(req2)
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
