package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testArtifactID = "44444444-4444-4444-4444-444444444444"

func testArtifactSummary() client.ArtifactSummary {
	group := "ghcr.io/pfenerty"
	return client.ArtifactSummary{
		Id: testArtifactID, Type: "container", Name: "ocidex", Group: &group,
		SbomCount: 9, SufficientSbomCount: 7, SigningStatus: "verified",
	}
}

func TestArtifactList(t *testing.T) {
	is := is.New(t)
	var got client.ArtifactFilter
	fake := &client.FakeClient{
		ListArtifactsFn: func(_ context.Context, filter client.ArtifactFilter, opts client.PageOpts) (client.CursorPage[client.ArtifactSummary], error) {
			got = filter
			is.Equal(opts.Offset, int32(10))
			return client.CursorPage[client.ArtifactSummary]{
				Data: []client.ArtifactSummary{testArtifactSummary()},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "artifact", "list",
		"--type", "application", "--name", "ocidex", "--include-insufficient", "--offset", "10")
	is.NoErr(err)
	is.Equal(got.Type, "application")
	is.Equal(got.Name, "ocidex")
	is.Equal(got.IncludeInsufficient, true)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[1], "ghcr.io/pfenerty/ocidex"))
	// Sufficient over total, so a tracked-but-useless artifact is visible as one.
	is.True(strings.Contains(lines[1], "7/9"))
}

// The plural is what people type; the singular is what the docs say.
func TestArtifactsAlias(t *testing.T) {
	is := is.New(t)
	called := false
	fake := &client.FakeClient{
		ListArtifactsFn: func(context.Context, client.ArtifactFilter, client.PageOpts) (client.CursorPage[client.ArtifactSummary], error) {
			called = true
			return client.CursorPage[client.ArtifactSummary]{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "artifacts", "list")
	is.NoErr(err)
	is.True(called)
}

func TestArtifactGetJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetArtifactFn: func(_ context.Context, id string) (client.ArtifactDetail, error) {
			is.Equal(id, testArtifactID)
			return client.ArtifactDetail{
				Id: id, Type: "container", Name: "ocidex", VersionCount: 4, SbomCount: 9,
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "artifact", "get", testArtifactID, "-o", "json")
	is.NoErr(err)

	var got client.ArtifactDetail
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.VersionCount, int64(4))
}

func testChangelog() client.Changelog {
	created := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	v1, v2 := "v1.0.0", "v1.1.0"
	arch, flavor := "amd64", "distroless"
	return client.Changelog{
		ArtifactId:             testArtifactID,
		HasSemver:              true,
		ResolvedMode:           "semver",
		AvailableArchitectures: &[]string{"amd64", "arm64"},
		AvailableFlavors:       &[]string{"distroless", "debian"},
		Entries: &[]client.ChangelogEntry{
			{
				From:    client.SBOMRef{Id: "a", SubjectVersion: &v1, Architecture: &arch, Flavor: &flavor, CreatedAt: created},
				To:      client.SBOMRef{Id: "b", SubjectVersion: &v2, Architecture: &arch, Flavor: &flavor, CreatedAt: created},
				Summary: client.ChangeSummary{Upgraded: 1, Added: 1},
				Changes: &[]client.ComponentDiff{
					{Direction: "upgraded", Type: "library", Name: "zlib", Version: ptr("1.3"), PreviousVersion: ptr("1.2.13")},
					{Direction: "added", Type: "library", Name: "curl", Version: ptr("8.7.1")},
				},
			},
		},
	}
}

func TestArtifactChangelog(t *testing.T) {
	is := is.New(t)
	var got client.GetArtifactChangelogParams
	fake := &client.FakeClient{
		GetArtifactChangelogFn: func(_ context.Context, id string, params client.GetArtifactChangelogParams) (client.Changelog, error) {
			is.Equal(id, testArtifactID)
			got = params
			return testChangelog(), nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "artifact", "changelog", testArtifactID,
		"--arch", "amd64", "--flavor", "distroless")
	is.NoErr(err)
	is.Equal(*got.Arch, "amd64")
	is.Equal(*got.Flavor, "distroless")
	is.True(got.SubjectVersion == nil) // unset flags stay absent, not empty

	is.True(strings.Contains(stdout, "v1.0.0 (amd64/distroless)"))
	is.True(strings.Contains(stdout, "-> v1.1.0"))
	is.True(strings.Contains(stdout, "zlib 1.2.13 -> 1.3"))
	is.True(strings.Contains(stdout, "curl 8.7.1"))

	// The axis values are guidance, not data: stderr, table mode only.
	is.True(strings.Contains(stderr, "architectures: amd64, arm64"))
	is.True(strings.Contains(stderr, "flavors: distroless, debian"))
	is.True(!strings.Contains(stdout, "architectures:"))
}

func TestArtifactChangelogJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetArtifactChangelogFn: func(context.Context, string, client.GetArtifactChangelogParams) (client.Changelog, error) {
			return testChangelog(), nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "artifact", "changelog", testArtifactID, "-o", "json")
	is.NoErr(err)
	is.Equal(stderr, "")

	var got client.Changelog
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.ResolvedMode, "semver")
	is.Equal(len(*got.Entries), 1)
}

func TestArtifactChangelogEmpty(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetArtifactChangelogFn: func(context.Context, string, client.GetArtifactChangelogParams) (client.Changelog, error) {
			return client.Changelog{ArtifactId: testArtifactID, ResolvedMode: "created_at"}, nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "artifact", "changelog", testArtifactID)
	is.NoErr(err)
	is.True(strings.Contains(stdout, "no version transitions"))
	// Ingest-time ordering is a caveat worth stating, not an error.
	is.True(strings.Contains(stderr, "no semver"))
}

func TestArtifactLicenseSummary(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetArtifactLicenseSummaryFn: func(_ context.Context, id string) (client.GetArtifactLicenseSummaryOutputBody, error) {
			is.Equal(id, testArtifactID)
			return client.GetArtifactLicenseSummaryOutputBody{
				Licenses: &[]client.LicenseCount{
					{Id: "1", Name: "Apache License 2.0", SpdxId: ptr("Apache-2.0"), Category: "permissive", ComponentCount: 220},
					{Id: "2", Name: "Some Vendor EULA", Category: "proprietary", ComponentCount: 1},
				},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "artifact", "license-summary", testArtifactID)
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 3)
	// SPDX id when there is one, because that is what tooling matches on.
	is.True(strings.Contains(lines[1], "Apache-2.0"))
	is.True(strings.Contains(lines[1], "220"))
	// Falling back to the name keeps a non-SPDX license from rendering blank.
	is.True(strings.Contains(lines[2], "Some Vendor EULA"))
}
