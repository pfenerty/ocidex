package service

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

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

func TestImageRefTag(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"tagged", "ghcr.io/pfenerty/ocidex:v1.2.3", "v1.2.3"},
		{"digest only", "ghcr.io/pfenerty/ocidex@sha256:" + strings.Repeat("a", 64), ""},
		{"tag and digest", "ghcr.io/pfenerty/ocidex:v1.2.3@sha256:" + strings.Repeat("a", 64), "v1.2.3"},
		{"untagged", "ghcr.io/pfenerty/ocidex", ""},
		// The colon here is the registry port, not a tag separator.
		{"port in host, no tag", "localhost:5005/ocidex", ""},
		{"port in host and tag", "localhost:5005/ocidex:dev", "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := imageRefTag(tt.ref); got != tt.want {
				t.Errorf("imageRefTag(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

// TestIngestResultCountSkip pins every non-ready reason to its own counter. A
// reason that fell through the switch would be counted as considered and not
// skipped, which reads as a silent success — precisely the collapse ADR-044 K5
// forbids.
func TestIngestResultCountSkip(t *testing.T) {
	reasons := []string{
		IngestReasonNoRegistry,
		IngestReasonRegistryDisabled,
		IngestReasonPatternExcluded,
		IngestReasonUnparseableRef,
	}
	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			var res IngestResult
			res.countSkip(reason)
			total := res.SkippedNoRegistry + res.SkippedRegistryDisabled +
				res.SkippedPatternExcluded + res.SkippedUnparseableRef
			if total != 1 {
				t.Errorf("countSkip(%q) filed %d skips, want exactly 1", reason, total)
			}
		})
	}
}

// img is a gap row reduced to the fields rollUpHosts reads.
func img(host, repo, reason string, pods, workloads int64, registryID string) UnknownImage {
	u := UnknownImage{
		RegistryHost: host, Repository: repo, Reason: reason,
		PodCount: pods, WorkloadCount: workloads,
	}
	if registryID != "" {
		name := registryID + "-name"
		u.RegistryID, u.RegistryName = &registryID, &name
	}
	return u
}

func TestRollUpHosts(t *testing.T) {
	hosts := rollUpHosts([]UnknownImage{
		// Two ghcr rows, one of them already ingestable. `ready` names no
		// registry to configure, so it must not inflate the host's counts.
		img("ghcr.io", "org/a", IngestReasonNoRegistry, 4, 2, ""),
		img("ghcr.io", "org/b", IngestReasonNoRegistry, 5, 3, ""),
		img("ghcr.io", "org/c", IngestReasonReady, 90, 90, "r-ok"),
		// A reference with no host has nowhere to send the reader.
		img("", "", IngestReasonUnparseableRef, 70, 70, ""),
		img("quay.io", "team/x", IngestReasonPatternExcluded, 1, 1, "r-quay"),
	})

	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d: %+v", len(hosts), hosts)
	}
	// Biggest gap first: that is the registry worth configuring next.
	if hosts[0].Host != "ghcr.io" || hosts[1].Host != "quay.io" {
		t.Fatalf("hosts not ordered by image count: %+v", hosts)
	}
	g := hosts[0]
	if g.ImageCount != 2 || g.PodCount != 9 || g.WorkloadCount != 5 {
		t.Errorf("ready row leaked into the ghcr.io totals: %+v", g)
	}
	if g.RegistryID != nil {
		t.Errorf("no_registry host named a registry: %v", *g.RegistryID)
	}
	// A matched-but-unusable registry has to be named, or "enable it" and
	// "widen its patterns" have nowhere to point.
	if hosts[1].RegistryID == nil || *hosts[1].RegistryID != "r-quay" {
		t.Errorf("quay.io lost its matched registry: %+v", hosts[1])
	}
}

// A host whose images hit several reasons is reported by the worst: adding a
// registry subsumes enabling one, which subsumes widening its patterns.
func TestRollUpHostsReportsWorstReason(t *testing.T) {
	tests := []struct {
		name    string
		reasons []string
		want    string
	}{
		{"excluded alone", []string{IngestReasonPatternExcluded}, IngestReasonPatternExcluded},
		{"disabled outranks excluded", []string{IngestReasonPatternExcluded, IngestReasonRegistryDisabled}, IngestReasonRegistryDisabled},
		{"missing outranks both", []string{IngestReasonRegistryDisabled, IngestReasonNoRegistry, IngestReasonPatternExcluded}, IngestReasonNoRegistry},
		{"order of arrival does not matter", []string{IngestReasonNoRegistry, IngestReasonPatternExcluded}, IngestReasonNoRegistry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := make([]UnknownImage, len(tt.reasons))
			for i, r := range tt.reasons {
				rows[i] = img("ghcr.io", "org/a", r, 1, 1, "r-1")
			}
			got := rollUpHosts(rows)
			if len(got) != 1 {
				t.Fatalf("want 1 host, got %d", len(got))
			}
			if got[0].Reason != tt.want {
				t.Errorf("reason = %q, want %q", got[0].Reason, tt.want)
			}
		})
	}
}

func TestRollUpHostsRepositories(t *testing.T) {
	// Distinct and sorted: the list is pasted straight into a registry's
	// Repositories field, where a duplicate is noise and an arbitrary order
	// makes two reads of the same gap look like different gaps.
	got := rollUpHosts([]UnknownImage{
		img("ghcr.io", "org/z", IngestReasonNoRegistry, 1, 1, ""),
		img("ghcr.io", "org/a", IngestReasonNoRegistry, 1, 1, ""),
		img("ghcr.io", "org/z", IngestReasonNoRegistry, 1, 1, ""),
	})
	if len(got) != 1 {
		t.Fatalf("want 1 host, got %d", len(got))
	}
	if want := []string{"org/a", "org/z"}; !slices.Equal(got[0].Repositories, want) {
		t.Errorf("repositories = %v, want %v", got[0].Repositories, want)
	}
	if got[0].RepositoryCount != 2 {
		t.Errorf("repository count = %d, want 2", got[0].RepositoryCount)
	}
}

// Past the cap the list is a prefix, and the count still reports the whole
// truth — a truncated list that reads as complete is exactly the quiet
// omission ADR-044 K5 exists to prevent.
func TestRollUpHostsCapsRepositoriesWithoutHidingTheTotal(t *testing.T) {
	rows := make([]UnknownImage, 0, maxHostRepositories+20)
	for i := 0; i < maxHostRepositories+20; i++ {
		rows = append(rows, img("ghcr.io", fmt.Sprintf("org/repo-%03d", i), IngestReasonNoRegistry, 1, 1, ""))
	}
	got := rollUpHosts(rows)[0]
	if len(got.Repositories) != maxHostRepositories {
		t.Errorf("repositories not capped: got %d", len(got.Repositories))
	}
	if got.RepositoryCount != int64(maxHostRepositories+20) {
		t.Errorf("repository count = %d, want %d", got.RepositoryCount, maxHostRepositories+20)
	}
	// Sorted before the cap, so the prefix is deterministic rather than
	// whatever order the rows happened to arrive in.
	if got.Repositories[0] != "org/repo-000" {
		t.Errorf("cap took an unsorted prefix: starts at %q", got.Repositories[0])
	}
}

func TestRollUpHostsIgnoresGapsWithNoRegistryRemedy(t *testing.T) {
	got := rollUpHosts([]UnknownImage{
		img("ghcr.io", "org/a", IngestReasonReady, 1, 1, "r-1"),
		img("", "", IngestReasonUnparseableRef, 1, 1, ""),
	})
	if len(got) != 0 {
		t.Errorf("want no hosts, got %+v", got)
	}
}

// The tenancy boundary is where one set of credentials stops working. On a
// multi-tenant host that is below the host itself, and a rollup that ignores it
// proposes one registry spanning owners it cannot all authenticate to.
func TestRegistryTenancyDepth(t *testing.T) {
	tests := []struct {
		host string
		want int
	}{
		// Public multi-tenant hosts: the first path segment is the account.
		{"ghcr.io", 1},
		{"quay.io", 1},
		{"docker.io", 1},
		{"registry-1.docker.io", 1},
		{"gcr.io", 1},
		{"us.gcr.io", 1},
		{"public.ecr.aws", 1},
		// Artifact Registry addresses a repository *within* a project, and a
		// reader-role service account is granted on the repository.
		{"europe-west4-docker.pkg.dev", 2},
		{"us-central1-docker.pkg.dev", 2},
		// The host already names the registry — splitting would invent a
		// boundary the registry does not have.
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com", 0},
		{"mycorp.azurecr.io", 0},
		// Single-tenant public registries. k8s.gcr.io matters: it ends in
		// .gcr.io but is one project serving everyone anonymously.
		{"registry.k8s.io", 0},
		{"k8s.gcr.io", 0},
		{"mcr.microsoft.com", 0},
		// An unknown host is far more often someone's own registry than a
		// multi-tenant one, and over-splitting costs catalog discovery.
		{"internal-registry.acme.corp", 0},
		{"zot.lan", 0},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := registryTenancyDepth(tt.host); got != tt.want {
				t.Errorf("registryTenancyDepth(%q) = %d, want %d", tt.host, got, tt.want)
			}
		})
	}
}

// A prefix may never swallow the whole repository: `ghcr.io/pause` would
// otherwise become a group per image, each proposing a registry serving one
// tag. At least one segment always remains the image.
func TestRegistryScopeLeavesAnImageBehind(t *testing.T) {
	tests := []struct {
		host, repo, want string
	}{
		{"ghcr.io", "pfenerty/ocidex-api", "ghcr.io/pfenerty"},
		{"ghcr.io", "pfenerty/ocidex/api", "ghcr.io/pfenerty"},
		{"europe-west4-docker.pkg.dev", "proj/repo/img", "europe-west4-docker.pkg.dev/proj/repo"},
		// Fewer segments than the depth wants: fall back rather than consume
		// the image name.
		{"europe-west4-docker.pkg.dev", "proj/img", "europe-west4-docker.pkg.dev/proj"},
		{"ghcr.io", "pause", "ghcr.io"},
		{"registry.k8s.io", "coredns/coredns", "registry.k8s.io"},
		{"zot.lan", "", "zot.lan"},
	}
	for _, tt := range tests {
		t.Run(tt.host+"/"+tt.repo, func(t *testing.T) {
			if got := registryScope(tt.host, tt.repo); got != tt.want {
				t.Errorf("registryScope(%q, %q) = %q, want %q", tt.host, tt.repo, got, tt.want)
			}
		})
	}
}

// The bug this fixes: two GitHub orgs on ghcr.io are two registries with two
// credentials, and one row covering both produces a registry that can
// authenticate to half its repositories.
func TestRollUpHostsSplitsAMultiTenantHost(t *testing.T) {
	got := rollUpHosts([]UnknownImage{
		img("ghcr.io", "orgA/api", IngestReasonNoRegistry, 3, 1, ""),
		img("ghcr.io", "orgA/web", IngestReasonNoRegistry, 2, 1, ""),
		img("ghcr.io", "orgB/tool", IngestReasonNoRegistry, 1, 1, ""),
	})
	if len(got) != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", len(got), got)
	}
	if got[0].Scope != "ghcr.io/orgA" || got[1].Scope != "ghcr.io/orgB" {
		t.Fatalf("groups not scoped by owner: %+v", got)
	}
	// Host stays the registry address: it is what goes in the form's URL.
	if got[0].Host != "ghcr.io" {
		t.Errorf("host = %q, want the registry address", got[0].Host)
	}
	if want := []string{"orgA/api", "orgA/web"}; !slices.Equal(got[0].Repositories, want) {
		t.Errorf("orgA repositories = %v, want %v", got[0].Repositories, want)
	}
	if got[0].ImageCount != 2 || got[1].ImageCount != 1 {
		t.Errorf("counts not split with the groups: %+v", got)
	}
}

// The other half of the same judgement: a host with no tenancy below it stays
// one row. Splitting registry.k8s.io by first segment would turn one anonymous
// public registry into a row per project, each with catalog discovery off.
func TestRollUpHostsKeepsASingleTenantHostWhole(t *testing.T) {
	got := rollUpHosts([]UnknownImage{
		img("registry.k8s.io", "coredns/coredns", IngestReasonNoRegistry, 2, 1, ""),
		img("registry.k8s.io", "etcd/etcd", IngestReasonNoRegistry, 1, 1, ""),
		img("internal-registry.acme.corp", "team-a/api", IngestReasonNoRegistry, 1, 1, ""),
		img("internal-registry.acme.corp", "team-b/web", IngestReasonNoRegistry, 1, 1, ""),
	})
	if len(got) != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", len(got), got)
	}
	for _, g := range got {
		if g.Scope != g.Host {
			t.Errorf("single-tenant host was split: scope %q, host %q", g.Scope, g.Host)
		}
		if g.ImageCount != 2 {
			t.Errorf("%s: image count = %d, want 2", g.Scope, g.ImageCount)
		}
	}
}

// Ordering is over groups, not hosts: the biggest group is the registry worth
// configuring next even when a smaller sibling shares its host.
func TestRollUpHostsOrdersGroupsByImageCount(t *testing.T) {
	got := rollUpHosts([]UnknownImage{
		img("ghcr.io", "small/a", IngestReasonNoRegistry, 1, 1, ""),
		img("quay.io", "mid/a", IngestReasonNoRegistry, 1, 1, ""),
		img("quay.io", "mid/b", IngestReasonNoRegistry, 1, 1, ""),
		img("ghcr.io", "big/a", IngestReasonNoRegistry, 1, 1, ""),
		img("ghcr.io", "big/b", IngestReasonNoRegistry, 1, 1, ""),
		img("ghcr.io", "big/c", IngestReasonNoRegistry, 1, 1, ""),
	})
	scopes := make([]string, 0, len(got))
	for _, g := range got {
		scopes = append(scopes, g.Scope)
	}
	want := []string{"ghcr.io/big", "quay.io/mid", "ghcr.io/small"}
	if !slices.Equal(scopes, want) {
		t.Errorf("group order = %v, want %v", scopes, want)
	}
}
