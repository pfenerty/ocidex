package git

import (
	"testing"

	"github.com/pfenerty/ocidex/internal/enrichment"
)

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
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "https url with .git suffix",
			raw:       "https://github.com/owner/repo.git",
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "git+https url",
			raw:       "git+https://github.com/owner/repo.git",
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantOK:    true,
		},
		{
			name:      "bare host/owner/repo",
			raw:       "github.com/owner/repo",
			wantHost:  "github.com",
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
