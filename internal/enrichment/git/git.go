// Package git implements the git source enricher. It resolves the source
// repository (host, owner, repo) from the oci-metadata enricher's sourceUrl
// output and, in a later story, fetches commit metadata from the host's API.
package git

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

// OCIDataReader reads the oci-metadata enricher's stored sourceUrl/revision
// for a given SBOM. Injected so the git enricher doesn't depend directly on
// the oci package or repository layer.
type OCIDataReader func(ctx context.Context, sbomID pgtype.UUID) (sourceURL, revision string, err error)

// Enricher resolves git commit metadata for container artifacts using the
// source URL recorded by the oci-metadata enricher.
type Enricher struct {
	ociReader OCIDataReader
}

// Option configures the git Enricher.
type Option func(*Enricher)

// WithOCIDataReader sets the seam used to read oci-metadata's output.
func WithOCIDataReader(r OCIDataReader) Option {
	return func(e *Enricher) { e.ociReader = r }
}

// NewEnricher creates a git enricher.
func NewEnricher(opts ...Option) *Enricher {
	e := &Enricher{}
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

// Enrich is implemented in story 2jb.4 (GitHub client).
func (e *Enricher) Enrich(_ context.Context, _ enrichment.SubjectRef) ([]byte, error) {
	return nil, errors.New("git: Enrich not implemented")
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
