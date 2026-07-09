// Package vuln implements the package-keyed vulnerability store: an OSV.dev
// client and a scheduled refresh that maps component purls to vulnerabilities.
// Per-SBOM vulnerability status is derived by joining component.purl against the
// store at read time, so a newly disclosed CVE filters up to every affected SBOM
// without re-enriching it.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL   = "https://api.osv.dev"
	defaultBatchSize = 1000 // OSV querybatch accepts up to 1000 queries per request
	defaultTimeout   = 30 * time.Second
	maxQueryPages    = 20 // guard against an unbounded page_token loop
)

// Record is the subset of an OSV vulnerability record that we persist. Raw holds
// the full JSON body for fidelity; the typed fields drive display and the derived
// severity/fixed-version columns.
type Record struct {
	ID               string           `json:"id"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Published        string           `json:"published"`
	Modified         string           `json:"modified"`
	Withdrawn        string           `json:"withdrawn"`
	Severity         []Severity       `json:"severity"`
	Affected         []Affected       `json:"affected"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
	Raw              json.RawMessage  `json:"-"`
}

// Reference is one entry in an OSV record's references list.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Severity is one OSV severity entry, e.g. {Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/..."}.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// DatabaseSpecific holds the ecosystem-specific metadata block present on both
// top-level OSV records and per-affected entries. The Go security database uses
// this to carry a plain-text severity label when no CVSS vector is available.
type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

// Affected describes one affected package and its version ranges.
type Affected struct {
	Package          AffectedPackage  `json:"package"`
	Ranges           []Range          `json:"ranges"`
	Versions         []string         `json:"versions"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

// AffectedPackage identifies the affected package.
type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

// Range is a set of introduced/fixed events over a version scheme.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one boundary in a Range; exactly one field is set.
type Event struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	Limit      string `json:"limit"`
}

// Client talks to the OSV.dev REST API.
type Client struct {
	baseURL   string
	http      *http.Client
	batchSize int
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the OSV API base URL (e.g. for tests).
func WithBaseURL(u string) Option {
	return func(c *Client) {
		if u != "" {
			c.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// WithHTTPClient overrides the HTTP client (e.g. to set a timeout).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// WithBatchSize overrides the querybatch chunk size.
func WithBatchSize(n int) Option {
	return func(c *Client) {
		if n > 0 && n <= defaultBatchSize {
			c.batchSize = n
		}
	}
}

// NewClient constructs an OSV client with sensible defaults.
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL:   defaultBaseURL,
		http:      &http.Client{Timeout: defaultTimeout},
		batchSize: defaultBatchSize,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// batchQuery / batchResult mirror the OSV /v1/querybatch request and response.
type batchQuery struct {
	Package   AffectedPackage `json:"package"`
	PageToken string          `json:"page_token,omitempty"`
}

type batchResult struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// QueryRef is a (ID, Modified) pair from an OSV querybatch response. Modified is
// the RFC3339 timestamp string as returned by the API; it is compared against the
// stored modified_at to detect unchanged records and skip unnecessary GETs.
type QueryRef struct {
	ID       string
	Modified string
}

// QueryPurls returns, for each input purl, the QueryRefs (ID + Modified) of
// vulnerabilities affecting it. OSV performs version matching server-side.
// Purls with no vulns map to an empty slice. Input is chunked to respect the
// OSV batch limit; per-purl pagination (next_page_token) is followed until
// exhausted or maxQueryPages is reached.
func (c *Client) QueryPurls(ctx context.Context, purls []string) (map[string][]QueryRef, error) {
	out := make(map[string][]QueryRef, len(purls))
	for start := 0; start < len(purls); start += c.batchSize {
		end := start + c.batchSize
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[start:end]
		if err := c.queryChunk(ctx, chunk, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *Client) queryChunk(ctx context.Context, purls []string, out map[string][]QueryRef) error {
	acc := make(map[string][]QueryRef, len(purls))

	pending := purls
	tokens := make(map[string]string, len(purls))
	for page := 0; len(pending) > 0; page++ {
		if page >= maxQueryPages {
			return fmt.Errorf("osv querybatch: exceeded %d pages", maxQueryPages)
		}

		body := struct {
			Queries []batchQuery `json:"queries"`
		}{Queries: make([]batchQuery, len(pending))}
		for i, p := range pending {
			body.Queries[i] = batchQuery{Package: AffectedPackage{Purl: p}, PageToken: tokens[p]}
		}

		var res batchResult
		if err := c.postJSON(ctx, "/v1/querybatch", body, &res); err != nil {
			return err
		}
		if len(res.Results) != len(pending) {
			return fmt.Errorf("osv querybatch: got %d results for %d queries", len(res.Results), len(pending))
		}

		next := make([]string, 0)
		for i, r := range res.Results {
			p := pending[i]
			for _, v := range r.Vulns {
				acc[p] = append(acc[p], QueryRef{ID: v.ID, Modified: v.Modified})
			}
			if r.NextPageToken != "" {
				tokens[p] = r.NextPageToken
				next = append(next, p)
			}
		}
		pending = next
	}

	for _, p := range purls {
		refs := acc[p]
		if refs == nil {
			refs = []QueryRef{}
		}
		out[p] = refs
	}
	return nil
}

// GetVuln fetches and parses a single vulnerability record by ID.
func (c *Client) GetVuln(ctx context.Context, id string) (*Record, error) {
	raw, err := c.get(ctx, "/v1/vulns/"+id)
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("osv decode vuln %s: %w", id, err)
	}
	rec.Raw = raw
	return &rec, nil
}

func (c *Client) postJSON(ctx context.Context, path string, reqBody, out any) error {
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("osv marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("osv build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	raw, err := c.do(req)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("osv decode %s: %w", path, err)
	}
	return nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("osv build request: %w", err)
	}
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv request %s: %w", req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv read %s: %w", req.URL.Path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv %s: status %d: %s", req.URL.Path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
