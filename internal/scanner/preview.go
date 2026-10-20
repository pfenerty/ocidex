package scanner

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/service"
)

// RepoPreview is what a walk of one repository would select (ADR-0053 S7).
type RepoPreview struct {
	Repository     string `json:"repository"`
	Matched        int    `json:"matched" doc:"Tags that pass the filter"`
	Selected       int    `json:"selected" doc:"Tags inside the window"`
	SkippedByLimit int    `json:"skipped_by_limit" doc:"Matching tags past tag_limit"`
	SkippedByAge   int    `json:"skipped_by_age" doc:"Matching tags older than max_tag_age_days, or with no build date while it is set"`
	Untagged       int    `json:"untagged" doc:"Untagged manifests inside the untagged window (include_untagged only)"`
	Platforms      int    `json:"platforms" doc:"Platforms of the newest selected tag, the sample the estimate multiplies by"`
	EstimatedSBOMs int    `json:"estimated_sboms" doc:"(selected tags x platforms) + untagged manifests; an estimate, since tags can share digests and platforms vary"`
	Error          string `json:"error,omitempty" doc:"Why this repository could not be previewed; the others still are"`
}

// RegistryPreview totals RepoPreview across every repository a walk would visit.
type RegistryPreview struct {
	Repositories   []RepoPreview `json:"repositories"`
	Selected       int           `json:"selected"`
	SkippedByLimit int           `json:"skipped_by_limit"`
	EstimatedSBOMs int           `json:"estimated_sboms"`
}

// PreviewRegistry runs the walk's selection for every repository and submits
// nothing. A created-order preview fetches the same build dates a walk would,
// so it is not free on a large registry.
func PreviewRegistry(ctx context.Context, reg service.Registry, egress netguard.Policy, logger *slog.Logger) (RegistryPreview, error) {
	scheme, host := registrySchemeHost(reg)
	baseURL := scheme + "://" + host
	client := registryClient(egress, 15*time.Second, derefStr(reg.AuthUsername), derefStr(reg.AuthToken))

	repos, err := matchingRepos(ctx, client, baseURL, reg, logger)
	if err != nil {
		return RegistryPreview{}, err
	}
	out := RegistryPreview{Repositories: make([]RepoPreview, 0, len(repos))}
	for _, repo := range repos {
		p := previewRepo(ctx, client, baseURL, repo, reg, logger)
		out.Repositories = append(out.Repositories, p)
		out.Selected += p.Selected
		out.SkippedByLimit += p.SkippedByLimit
		out.EstimatedSBOMs += p.EstimatedSBOMs
	}
	return out, nil
}

func previewRepo(ctx context.Context, client *http.Client, baseURL, repo string, reg service.Registry, logger *slog.Logger) RepoPreview {
	p := RepoPreview{Repository: repo}
	window, matched, err := selectRepoTags(ctx, client, baseURL, repo, reg, logger)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Matched, p.Selected = matched, len(window.Selected)
	p.SkippedByLimit, p.SkippedByAge = window.SkippedByLimit, window.SkippedByAge
	if len(window.Selected) > 0 {
		p.Platforms = tagPlatforms(ctx, client, baseURL, repo, window.Selected[0])
	}
	if reg.IncludeUntagged {
		untagged, _, err := selectUntagged(ctx, client, baseURL, repo, reg)
		if err != nil {
			p.Error = err.Error()
		}
		p.Untagged = len(untagged.Selected)
	}
	p.EstimatedSBOMs = p.Selected*p.Platforms + p.Untagged
	return p
}

// tagPlatforms is how many SBOMs one tag fans out to: its platform count for
// an index, 1 for a single image, 0 when it cannot be read.
func tagPlatforms(ctx context.Context, client *http.Client, baseURL, repo, tag string) int {
	info, err := ociHeadManifest(ctx, client, baseURL, repo, tag)
	if err != nil || info.digest == "" {
		return 0
	}
	if !isIndexMediaType(info.mediaType) {
		return 1
	}
	platforms, err := ociExpandIndex(ctx, client, baseURL, repo, info.digest)
	if err != nil {
		return 0
	}
	return len(platforms)
}

// TagInWindow reports whether a pushed tag falls inside its repository's scan
// window (ADR-0053 S8). Under created order it always does: a push is almost
// always the newest build, and the next walk's view is the one retention acts
// on. Under semver and lexical it costs one tag list. tag must already pass
// the registry's filter.
func TagInWindow(ctx context.Context, reg service.Registry, repo, tag string, egress netguard.Policy, logger *slog.Logger) (bool, error) {
	if reg.TagLimit == 0 || reg.EffectiveTagOrder() == service.TagOrderCreated {
		return true, nil
	}
	scheme, host := registrySchemeHost(reg)
	client := registryClient(egress, 15*time.Second, derefStr(reg.AuthUsername), derefStr(reg.AuthToken))
	window, _, err := selectRepoTags(ctx, client, scheme+"://"+host, repo, reg, logger)
	if err != nil {
		return false, err
	}
	return slices.Contains(window.Selected, tag), nil
}
