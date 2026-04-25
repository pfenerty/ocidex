package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pfenerty/ocidex/internal/service"
)

func init() {
	RegisterDiscoverer("zot", func(_ service.Registry) ManifestDiscoverer {
		return &zotDiscoverer{}
	})
}

// zotDiscoverer uses Zot's GraphQL search extension to list all manifests.
type zotDiscoverer struct{}

func (z *zotDiscoverer) DiscoverManifests(ctx context.Context, client *http.Client, baseURL, repo string) ([]DiscoveredManifest, error) {
	query := fmt.Sprintf(`{ ImageList(repo: %q) { Results { Digest MediaType Tag } } }`, repo)
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, fmt.Errorf("marshaling query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v2/_zot/ext/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("zot search request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("zot search extension not available (HTTP %d); enable the search extension in zot config", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zot search returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			ImageList struct {
				Results []struct {
					Digest    string `json:"Digest"`
					MediaType string `json:"MediaType"`
					Tag       string `json:"Tag"`
				} `json:"Results"`
			} `json:"ImageList"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding zot search response: %w", err)
	}

	manifests := make([]DiscoveredManifest, 0, len(result.Data.ImageList.Results))
	for _, r := range result.Data.ImageList.Results {
		if r.Digest == "" {
			continue
		}
		manifests = append(manifests, DiscoveredManifest{
			Digest:    r.Digest,
			MediaType: r.MediaType,
			Tag:       r.Tag,
		})
	}
	return manifests, nil
}
