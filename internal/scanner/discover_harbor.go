package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pfenerty/ocidex/internal/service"
)

func init() {
	RegisterDiscoverer("harbor", func(reg service.Registry) ManifestDiscoverer {
		return &harborDiscoverer{
			authUsername: derefStr(reg.AuthUsername),
			authToken:    derefStr(reg.AuthToken),
		}
	})
}

// harborDiscoverer uses Harbor's REST API to list all artifacts including untagged.
type harborDiscoverer struct {
	authUsername string
	authToken    string
}

func (h *harborDiscoverer) DiscoverManifests(ctx context.Context, client *http.Client, baseURL, repo string) ([]DiscoveredManifest, error) {
	project, repoPath, ok := splitHarborRepo(repo)
	if !ok {
		return nil, fmt.Errorf("cannot split Harbor repo %q into project/repository", repo)
	}
	encodedRepo := url.PathEscape(repoPath)

	var all []DiscoveredManifest
	page := 1
	const pageSize = 100
	for {
		endpoint := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?page=%d&page_size=%d",
			baseURL, project, encodedRepo, page, pageSize)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		if h.authToken != "" {
			username := h.authUsername
			if username == "" {
				username = "ocidex"
			}
			req.SetBasicAuth(username, h.authToken)
		}

		resp, err := client.Do(req) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("harbor artifacts request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("harbor artifacts returned HTTP %d", resp.StatusCode)
		}

		var artifacts []struct {
			Digest    string `json:"digest"`
			MediaType string `json:"media_type"`
			Tags      []struct {
				Name string `json:"name"`
			} `json:"tags"`
			ExtraAttrs struct {
				Architecture string `json:"architecture"`
			} `json:"extra_attrs"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&artifacts); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decoding harbor response: %w", err)
		}
		resp.Body.Close()

		for _, a := range artifacts {
			if a.Digest == "" {
				continue
			}
			tag := ""
			if len(a.Tags) > 0 {
				tag = a.Tags[0].Name
			}
			all = append(all, DiscoveredManifest{
				Digest:    a.Digest,
				MediaType: a.MediaType,
				Tag:       tag,
				Arch:      a.ExtraAttrs.Architecture,
			})
		}

		if len(artifacts) < pageSize {
			break
		}
		page++
	}
	return all, nil
}

// splitHarborRepo splits "project/repo/path" into ("project", "repo/path").
func splitHarborRepo(repo string) (project, repoPath string, ok bool) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
