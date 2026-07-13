package git

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

const testCommitJSON = `{
	"sha": "abc123def456",
	"html_url": "https://github.com/owner/repo/commit/abc123def456",
	"commit": {
		"author": {"name": "Alice Author", "email": "alice@example.com", "date": "2026-01-01T00:00:00Z"},
		"committer": {"name": "Bob Committer", "email": "bob@example.com", "date": "2026-01-02T00:00:00Z"},
		"message": "Fix the thing\n\nLonger explanation body."
	},
	"parents": [{"sha": "parent1"}, {"sha": "parent2"}]
}`

func TestEnricher_Name(t *testing.T) {
	if got := NewEnricher().Name(); got != "git" {
		t.Errorf("Name() = %q, want %q", got, "git")
	}
}

func TestEnricher_CanEnrich(t *testing.T) {
	tests := []struct {
		name string
		ref  enrichment.SubjectRef
		want bool
	}{
		{
			name: "with digest",
			ref:  enrichment.SubjectRef{Digest: "sha256:abc123"},
			want: true,
		},
		{
			name: "without digest",
			ref:  enrichment.SubjectRef{},
			want: false,
		},
	}
	e := NewEnricher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.CanEnrich(tt.ref); got != tt.want {
				t.Errorf("CanEnrich() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSourceURL(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantHost  string
		wantOwner string
		wantRepo  string
		wantOK    bool
	}{
		{
			name:      "https url",
			raw:       "https://github.com/owner/repo",
			wantHost:  githubHost,
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "https url with .git suffix",
			raw:       "https://github.com/owner/repo.git",
			wantHost:  githubHost,
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "git+https url",
			raw:       "git+https://github.com/owner/repo.git",
			wantHost:  githubHost,
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "bare host/owner/repo",
			raw:       "github.com/owner/repo",
			wantHost:  githubHost,
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:   "empty string",
			raw:    "",
			wantOK: false,
		},
		{
			name:   "invalid url",
			raw:    "not a url",
			wantOK: false,
		},
		{
			name:   "missing repo segment",
			raw:    "https://github.com/owner",
			wantOK: false,
		},
		{
			name:   "empty path",
			raw:    "https://github.com/",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, owner, repo, ok := parseSourceURL(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("parseSourceURL(%q) ok = %v, want %v", tt.raw, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if host != tt.wantHost || owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("parseSourceURL(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.raw, host, owner, repo, tt.wantHost, tt.wantOwner, tt.wantRepo)
			}
		})
	}
}

func fakeOCIReader(sourceURL, revision string, err error) OCIDataReader {
	return func(_ context.Context, _ pgtype.UUID) (string, string, error) {
		return sourceURL, revision, err
	}
}

func TestEnricher_Enrich_Success(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/repos/owner/repo/commits/deadbeef" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testCommitJSON))
	}))
	defer srv.Close()

	e := NewEnricher(
		WithOCIDataReader(fakeOCIReader("https://github.com/owner/repo", "deadbeef", nil)),
		WithHTTPClient(srv.Client()),
		WithTokenResolver(func(_ context.Context, host string) string {
			if host != githubHost {
				t.Errorf("tokenResolver called with unexpected host %q", host)
			}
			return "sekret"
		}),
	)
	e.baseURL = srv.URL

	data, err := e.Enrich(context.Background(), enrichment.SubjectRef{Digest: "sha256:abc"})
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	if gotAuth != "Bearer sekret" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer sekret")
	}

	var got commitMetadata
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	want := commitMetadata{
		Resolved:       true,
		Host:           githubHost,
		Owner:          "owner",
		Repo:           "repo",
		CommitSHA:      "abc123def456",
		CommitURL:      "https://github.com/owner/repo/commit/abc123def456",
		AuthorName:     "Alice Author",
		AuthorEmail:    "alice@example.com",
		AuthoredAt:     "2026-01-01T00:00:00Z",
		CommitterName:  "Bob Committer",
		CommitterEmail: "bob@example.com",
		CommittedAt:    "2026-01-02T00:00:00Z",
		MessageSubject: "Fix the thing",
		Parents:        []string{"parent1", "parent2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commitMetadata = %+v, want %+v", got, want)
	}
}

func TestEnricher_Enrich_Unresolved(t *testing.T) {
	tests := []struct {
		name      string
		sourceURL string
		revision  string
	}{
		{name: "empty revision", sourceURL: "https://github.com/owner/repo", revision: ""},
		{name: "unparsable source URL", sourceURL: "", revision: "deadbeef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				called = true
				return nil, fmt.Errorf("unexpected request")
			})}
			e := NewEnricher(
				WithOCIDataReader(fakeOCIReader(tt.sourceURL, tt.revision, nil)),
				WithHTTPClient(client),
			)

			data, err := e.Enrich(context.Background(), enrichment.SubjectRef{Digest: "sha256:abc"})
			if err != nil {
				t.Fatalf("Enrich() error = %v", err)
			}
			if called {
				t.Fatal("Enrich() made an HTTP call for an unresolved source")
			}

			var got commitMetadata
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
			if got.Resolved {
				t.Errorf("Resolved = true, want false")
			}
			if got.Reason == "" {
				t.Error("Reason is empty, want a reason string")
			}
		})
	}
}

func TestEnricher_Enrich_UnsupportedHost(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		called = true
		return nil, fmt.Errorf("unexpected request")
	})}
	e := NewEnricher(
		WithOCIDataReader(fakeOCIReader("https://gitlab.com/owner/repo", "deadbeef", nil)),
		WithHTTPClient(client),
	)

	data, err := e.Enrich(context.Background(), enrichment.SubjectRef{Digest: "sha256:abc"})
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}
	if called {
		t.Fatal("Enrich() made an HTTP call for an unsupported host")
	}

	var got commitMetadata
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.Resolved {
		t.Errorf("Resolved = true, want false")
	}
	if got.Reason != "unsupported host" {
		t.Errorf("Reason = %q, want %q", got.Reason, "unsupported host")
	}
}

func TestEnricher_Enrich_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer srv.Close()

	e := NewEnricher(
		WithOCIDataReader(fakeOCIReader("https://github.com/owner/repo", "deadbeef", nil)),
		WithHTTPClient(srv.Client()),
	)
	e.baseURL = srv.URL

	data, err := e.Enrich(context.Background(), enrichment.SubjectRef{Digest: "sha256:abc"})
	if err == nil {
		t.Fatal("Enrich() error = nil, want non-nil")
	}
	if data != nil {
		t.Errorf("data = %v, want nil", data)
	}
}

func TestEnricher_Enrich_OCIReaderError(t *testing.T) {
	wantErr := fmt.Errorf("oci reader boom")
	e := NewEnricher(WithOCIDataReader(fakeOCIReader("", "", wantErr)))

	data, err := e.Enrich(context.Background(), enrichment.SubjectRef{Digest: "sha256:abc"})
	if err == nil {
		t.Fatal("Enrich() error = nil, want non-nil")
	}
	if data != nil {
		t.Errorf("data = %v, want nil", data)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
