// Package git implements the git source enricher. It resolves the source
// repository (host, owner, repo) from the oci-metadata enricher's sourceUrl
// output and fetches the corresponding commit's metadata from GitHub.
package git

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

const (
	defaultBaseURL = "https://api.github.com"
	defaultTimeout = 15 * time.Second
	githubHost     = "github.com"
)

// OCIDataReader reads the oci-metadata enricher's stored sourceUrl/revision
// for a given SBOM. Injected so the git enricher doesn't depend directly on
// the oci package or repository layer.
type OCIDataReader func(ctx context.Context, sbomID pgtype.UUID) (sourceURL, revision string, err error)

// Enricher resolves git commit metadata for container artifacts using the
// source URL recorded by the oci-metadata enricher.
type Enricher struct {
	ociReader     OCIDataReader
	httpClient    *http.Client
	tokenResolver TokenResolver
	baseURL       string
}

// TokenResolver resolves a per-host auth token used for the GitHub API
// request. Returns an empty string when no token should be sent (mirrors
// oci.WithCredentialResolver's per-host resolver shape).
type TokenResolver func(ctx context.Context, host string) string

// Option configures the git Enricher.
type Option func(*Enricher)

// WithTokenResolver sets the per-host token resolver used to authenticate
// GitHub API requests.
func WithTokenResolver(fn TokenResolver) Option {
	return func(e *Enricher) { e.tokenResolver = fn }
}

// WithHTTPClient overrides the HTTP client (e.g. for tests or timeouts).
func WithHTTPClient(h *http.Client) Option {
	return func(e *Enricher) {
		if h != nil {
			e.httpClient = h
		}
	}
}

// WithOCIDataReader sets the seam used to read oci-metadata's output.
func WithOCIDataReader(r OCIDataReader) Option {
	return func(e *Enricher) { e.ociReader = r }
}

// NewEnricher creates a git enricher.
func NewEnricher(opts ...Option) *Enricher {
	e := &Enricher{
		httpClient: &http.Client{Timeout: defaultTimeout},
		baseURL:    defaultBaseURL,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Name returns the enricher identifier.
func (e *Enricher) Name() string { return "git" }

// CanEnrich returns true for artifacts with a digest.
func (e *Enricher) CanEnrich(ref enrichment.SubjectRef) bool {
	return ref.Digest != ""
}

// commitMetadata is the JSON shape persisted to enrichment.data. Resolved is
// false (with Reason set) when the source URL/revision can't be resolved to a
// GitHub commit lookup; this is not an error — the enricher ran successfully,
// it just had nothing to enrich (matches the oci/provenance soft-failure
// convention: expected non-resolution is encoded in the JSON, not a Go error).
type commitMetadata struct {
	Resolved       bool     `json:"resolved"`
	Reason         string   `json:"reason,omitempty"`
	Host           string   `json:"host,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	Repo           string   `json:"repo,omitempty"`
	CommitSHA      string   `json:"commitSha,omitempty"`
	CommitURL      string   `json:"commitUrl,omitempty"`
	AuthorName     string   `json:"authorName,omitempty"`
	AuthorEmail    string   `json:"authorEmail,omitempty"`
	AuthoredAt     string   `json:"authoredAt,omitempty"`
	CommitterName  string   `json:"committerName,omitempty"`
	CommitterEmail string   `json:"committerEmail,omitempty"`
	CommittedAt    string   `json:"committedAt,omitempty"`
	MessageSubject string   `json:"messageSubject,omitempty"`
	Parents        []string `json:"parents,omitempty"`
}

// githubCommit is the subset of the GitHub "get a commit" REST response
// (https://docs.github.com/en/rest/commits/commits#get-a-commit) that we use.
type githubCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Author struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Date  string `json:"date"`
		} `json:"author"`
		Committer struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Date  string `json:"date"`
		} `json:"committer"`
		Message string `json:"message"`
	} `json:"commit"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
}

// Enrich reads the oci-metadata enricher's sourceUrl/revision for the subject
// and fetches the corresponding commit from GitHub. An unresolvable source
// (missing/unparsable sourceUrl, missing revision, or a non-GitHub host)
// yields a JSON result with resolved=false and no error. A GitHub API
// failure (network error, 404/403/rate-limit, malformed response) is
// returned as a Go error.
func (e *Enricher) Enrich(ctx context.Context, ref enrichment.SubjectRef) ([]byte, error) {
	sourceURL, revision, err := e.ociReader(ctx, ref.SBOMId)
	if err != nil {
		return nil, err
	}

	host, owner, repo, ok := parseSourceURL(sourceURL)
	if !ok || revision == "" {
		return json.Marshal(commitMetadata{Reason: "unresolved source URL or revision"})
	}
	if host != githubHost {
		return json.Marshal(commitMetadata{Reason: "unsupported host"})
	}

	commit, err := e.fetchCommit(ctx, host, owner, repo, revision)
	if err != nil {
		return nil, err
	}

	subject := commit.Commit.Message
	if i := strings.IndexByte(subject, '\n'); i >= 0 {
		subject = subject[:i]
	}
	subject = strings.TrimSpace(subject)

	parents := make([]string, len(commit.Parents))
	for i, p := range commit.Parents {
		parents[i] = p.SHA
	}

	return json.Marshal(commitMetadata{
		Resolved:       true,
		Host:           host,
		Owner:          owner,
		Repo:           repo,
		CommitSHA:      commit.SHA,
		CommitURL:      commit.HTMLURL,
		AuthorName:     commit.Commit.Author.Name,
		AuthorEmail:    commit.Commit.Author.Email,
		AuthoredAt:     commit.Commit.Author.Date,
		CommitterName:  commit.Commit.Committer.Name,
		CommitterEmail: commit.Commit.Committer.Email,
		CommittedAt:    commit.Commit.Committer.Date,
		MessageSubject: subject,
		Parents:        parents,
	})
}

// fetchCommit performs the GitHub "get a commit" request and decodes the
// response. Non-2xx responses (404 not found, 403 forbidden/rate-limited)
// are returned as errors.
func (e *Enricher) fetchCommit(ctx context.Context, host, owner, repo, revision string) (*githubCommit, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", e.baseURL, owner, repo, revision)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("git: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if e.tokenResolver != nil {
		if token := e.tokenResolver(ctx, host); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("git: request %s/%s@%s: %w", owner, repo, revision, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("git: read response %s/%s@%s: %w", owner, repo, revision, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("git: github commit lookup %s/%s@%s: status %d: %s",
			owner, repo, revision, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var commit githubCommit
	if err := json.Unmarshal(body, &commit); err != nil {
		return nil, fmt.Errorf("git: decode commit %s/%s@%s: %w", owner, repo, revision, err)
	}
	return &commit, nil
}

// parseSourceURL extracts host, owner, repo from a source-code URL such as
// oci-metadata's sourceUrl field. Host is returned generically (not
// hardcoded to github.com) so a future GitLab adapter can reuse this parser.
// Recognized forms: https://host/owner/repo(.git), git+https://host/owner/repo(.git),
// and bare host/owner/repo. Anything else returns ok=false.
func parseSourceURL(raw string) (host, owner, repo string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", "", false
	}
	s = strings.TrimPrefix(s, "git+")
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return u.Host, parts[0], parts[1], true
}
