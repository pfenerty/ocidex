package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/pfenerty/ocidex/internal/service"
)

func init() {
	RegisterDiscoverer("ghcr", func(reg service.Registry) ManifestDiscoverer {
		return &ghcrDiscoverer{
			authToken: derefStr(reg.AuthToken),
		}
	})
}

// ghcrDiscoverer uses the GitHub Packages API to list all container versions.
type ghcrDiscoverer struct {
	authToken string
}

func (g *ghcrDiscoverer) DiscoverManifests(ctx context.Context, _ *http.Client, _, repo string) ([]DiscoveredManifest, error) {
	owner, name, ok := splitGHCRRepo(repo)
	if !ok {
		return nil, fmt.Errorf("cannot split GHCR repo %q into owner/name", repo)
	}

	// Try org endpoint first, fall back to user endpoint.
	versions, err := g.listVersions(ctx, "orgs", owner, name)
	if err != nil {
		versions, err = g.listVersions(ctx, "users", owner, name)
		if err != nil {
			return nil, err
		}
	}
	return versions, nil
}

func (g *ghcrDiscoverer) listVersions(ctx context.Context, ownerType, owner, name string) ([]DiscoveredManifest, error) {
	client := &http.Client{}
	endpoint := fmt.Sprintf("https://api.github.com/%s/%s/packages/container/%s/versions?per_page=100",
		ownerType, owner, name)

	var all []DiscoveredManifest
	for endpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if g.authToken != "" {
			req.Header.Set("Authorization", "Bearer "+g.authToken)
		}

		resp, err := client.Do(req) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("github packages request: %w", err)
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, fmt.Errorf("github packages returned 404 for %s/%s/%s", ownerType, owner, name)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("github packages returned HTTP %d", resp.StatusCode)
		}

		var versions []struct {
			Name     string `json:"name"`
			Metadata struct {
				Container struct {
					Tags []string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decoding github response: %w", err)
		}
		resp.Body.Close()

		for _, v := range versions {
			if v.Name == "" {
				continue
			}
			tag := ""
			if len(v.Metadata.Container.Tags) > 0 {
				tag = v.Metadata.Container.Tags[0]
			}
			all = append(all, DiscoveredManifest{
				Digest:    v.Name,
				MediaType: "application/vnd.oci.image.manifest.v1+json", // GitHub API doesn't expose media type; assume OCI
				Tag:       tag,
			})
		}

		endpoint = parseNextLink(resp.Header.Get("Link"))
	}
	return all, nil
}

// splitGHCRRepo splits "owner/name" or "owner/nested/name" into (owner, name).
func splitGHCRRepo(repo string) (owner, name string, ok bool) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// parseNextLink extracts the "next" URL from a GitHub Link header.
func parseNextLink(header string) string {
	m := linkNextRe.FindStringSubmatch(header)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
