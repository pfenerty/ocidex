package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// createdCacheMax bounds the digest→created cache. A digest's build date never
// changes, so entries never go stale; the bound only caps memory, and a full
// cache is simply emptied.
const createdCacheMax = 100_000

// createdCache remembers each digest's build date across walks, so a registry
// ordered by created pays the manifest and config fetches once per digest and
// one HEAD per tag after that (ADR-0053 S2).
var createdCache = struct {
	sync.Mutex
	m map[string]createdEntry
}{m: make(map[string]createdEntry)}

type createdEntry struct {
	t  time.Time
	ok bool
}

func cachedCreated(digest string, fetch func() (time.Time, bool)) (time.Time, bool) {
	createdCache.Lock()
	e, hit := createdCache.m[digest]
	createdCache.Unlock()
	if hit {
		return e.t, e.ok
	}
	t, ok := fetch()
	createdCache.Lock()
	if len(createdCache.m) >= createdCacheMax {
		clear(createdCache.m)
	}
	createdCache.m[digest] = createdEntry{t: t, ok: ok}
	createdCache.Unlock()
	return t, ok
}

// tagCreatedFunc returns the build date of a tag's image: one HEAD for the
// digest, then the cached or fetched date of that digest.
func tagCreatedFunc(ctx context.Context, c *http.Client, baseURL, repo string) service.CreatedFunc {
	return func(tag string) (time.Time, bool) {
		info, err := ociHeadManifest(ctx, c, baseURL, repo, tag)
		if err != nil || info.digest == "" {
			return time.Time{}, false
		}
		return cachedCreated(info.digest, func() (time.Time, bool) {
			return manifestCreated(ctx, c, baseURL, repo, info.digest, info.mediaType)
		})
	}
}

// digestCreatedFunc is tagCreatedFunc for discovered manifests, whose digest
// and media type are already known.
func digestCreatedFunc(ctx context.Context, c *http.Client, baseURL, repo string, manifests map[string]DiscoveredManifest) service.CreatedFunc {
	return func(digest string) (time.Time, bool) {
		return cachedCreated(digest, func() (time.Time, bool) {
			return manifestCreated(ctx, c, baseURL, repo, digest, manifests[digest].MediaType)
		})
	}
}

// manifestCreated reads a manifest's build date with the precedence
// ociGetImageMetadata applies. An index uses its own created annotation, else
// the date of its first platform manifest.
func manifestCreated(ctx context.Context, c *http.Client, baseURL, repo, digest, mediaType string) (time.Time, bool) {
	if isIndexMediaType(mediaType) {
		created, first, err := ociIndexCreated(ctx, c, baseURL, repo, digest)
		if err != nil {
			return time.Time{}, false
		}
		if t, ok := parseCreated(created); ok {
			return t, true
		}
		if first == "" {
			return time.Time{}, false
		}
		return parseCreated(ociGetImageMetadata(ctx, c, baseURL, repo, first).buildDate)
	}
	return parseCreated(ociGetImageMetadata(ctx, c, baseURL, repo, digest).buildDate)
}

func parseCreated(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	return t, err == nil
}

// ociIndexCreated fetches an image index and returns its
// org.opencontainers.image.created annotation and the digest of the first
// platform manifest ociExpandIndex would return.
func ociIndexCreated(ctx context.Context, c *http.Client, baseURL, repo, indexDigest string) (created, first string, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v2/"+repo+"/manifests/"+indexDigest, nil)
	req.Header.Set("Accept", strings.Join([]string{mediaTypeOCIIndex, mediaTypeDockerList}, ","))
	resp, err := c.Do(req) //nolint:gosec
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("index GET returned HTTP %d", resp.StatusCode)
	}
	var index struct {
		Annotations map[string]string `json:"annotations"`
		Manifests   []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
		return "", "", fmt.Errorf("decoding index: %w", err)
	}
	for _, m := range index.Manifests {
		if m.Digest != "" && m.Platform.OS != "" && m.Platform.OS != "unknown" {
			first = m.Digest
			break
		}
	}
	return index.Annotations["org.opencontainers.image.created"], first, nil
}
