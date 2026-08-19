package service

import "testing"

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		wantHost string
		wantRepo string
	}{
		{"tagged ghcr ref", "ghcr.io/pfenerty/ocidex-api:v1.2.3", "ghcr.io", "pfenerty/ocidex-api"},
		{"digest ref", "ghcr.io/pfenerty/api@sha256:abc", "ghcr.io", "pfenerty/api"},
		{"tag and digest", "quay.io/team/app:v1@sha256:abc", "quay.io", "team/app"},
		{"port in host", "localhost:5005/ocidex/api:dev", "localhost:5005", "ocidex/api"},
		{"docker hub alias normalized", "docker.io/library/nginx:1.27", "registry-1.docker.io", "library/nginx"},
		{"deep repository path", "registry.example.com/a/b/c/app:v1", "registry.example.com", "a/b/c/app"},
		{"no tag", "ghcr.io/pfenerty/api", "ghcr.io", "pfenerty/api"},

		// A reference with no host is not assumed to be Docker Hub. Guessing
		// would produce an ingest attempt against a registry the cluster may
		// not use at all.
		{"bare name", "nginx", "", ""},
		{"implicit docker hub path", "library/nginx:1.27", "", ""},
		{"bare identifier", "sha256:aaaa", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, repo := SplitImageRef(tt.ref)
			if host != tt.wantHost || repo != tt.wantRepo {
				t.Errorf("SplitImageRef(%q) = (%q, %q), want (%q, %q)",
					tt.ref, host, repo, tt.wantHost, tt.wantRepo)
			}
		})
	}
}

func TestResolveIngestTarget(t *testing.T) {
	enabled := Registry{ID: "r-ghcr", Name: "ghcr", URL: "https://ghcr.io", Enabled: true}
	disabled := Registry{ID: "r-off", Name: "ghcr-old", URL: "ghcr.io", Enabled: false}
	narrow := Registry{
		ID: "r-narrow", Name: "quay-team", URL: "quay.io", Enabled: true,
		RepositoryPatterns: []string{"team/**"},
	}

	tests := []struct {
		name         string
		ref          string
		registries   []Registry
		wantReason   string
		wantRegistry string // "" means none named
	}{
		{
			name:       "enabled registry serving the host",
			ref:        "ghcr.io/pfenerty/api:v1",
			registries: []Registry{enabled},
			wantReason: IngestReasonReady, wantRegistry: "r-ghcr",
		},
		{
			// "switched off" and "never configured" have different remedies,
			// so the disabled registry must be named rather than reported as
			// an absent one.
			name:       "host matches only a disabled registry",
			ref:        "ghcr.io/pfenerty/api:v1",
			registries: []Registry{disabled},
			wantReason: IngestReasonRegistryDisabled, wantRegistry: "r-off",
		},
		{
			name:       "an enabled registry outranks a disabled one for the same host",
			ref:        "ghcr.io/pfenerty/api:v1",
			registries: []Registry{disabled, enabled},
			wantReason: IngestReasonReady, wantRegistry: "r-ghcr",
		},
		{
			// Nothing is broken here: the exclusion is deliberate, and saying
			// so stops it being read as a failure to fix.
			name:       "repository excluded by the registry's patterns",
			ref:        "quay.io/other/app:v1",
			registries: []Registry{narrow},
			wantReason: IngestReasonPatternExcluded, wantRegistry: "r-narrow",
		},
		{
			name:       "repository accepted by the registry's patterns",
			ref:        "quay.io/team/app:v1",
			registries: []Registry{narrow},
			wantReason: IngestReasonReady, wantRegistry: "r-narrow",
		},
		{
			name:       "no registry configured for the host",
			ref:        "gcr.io/some/app:v1",
			registries: []Registry{enabled, narrow},
			wantReason: IngestReasonNoRegistry, wantRegistry: "",
		},
		{
			// The K3 gap seen from the ingest side: a reference with no host
			// gives nothing to resolve against.
			name:       "reference carries no host",
			ref:        "nginx:1.27",
			registries: []Registry{enabled},
			wantReason: IngestReasonUnparseableRef, wantRegistry: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, repo := SplitImageRef(tt.ref)
			img := UnknownImage{ImageRef: tt.ref, RegistryHost: host, Repository: repo}
			resolveIngestTarget(&img, tt.registries)

			if img.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", img.Reason, tt.wantReason)
			}
			if img.Ingestable() != (tt.wantReason == IngestReasonReady) {
				t.Errorf("Ingestable() = %v for reason %q", img.Ingestable(), img.Reason)
			}
			switch {
			case tt.wantRegistry == "":
				if img.RegistryID != nil {
					t.Errorf("named registry %q, want none", *img.RegistryID)
				}
			case img.RegistryID == nil:
				t.Errorf("named no registry, want %q", tt.wantRegistry)
			case *img.RegistryID != tt.wantRegistry:
				t.Errorf("registry = %q, want %q", *img.RegistryID, tt.wantRegistry)
			}
		})
	}
}
