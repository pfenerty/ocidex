package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testComponentID = "55555555-5555-5555-5555-555555555555"

func TestComponentList(t *testing.T) {
	is := is.New(t)
	var got client.DistinctComponentFilter
	fake := &client.FakeClient{
		SearchDistinctComponentsFn: func(_ context.Context, filter client.DistinctComponentFilter, opts client.PageOpts) (client.Page[client.DistinctComponentSummary], error) {
			got = filter
			is.Equal(opts.Limit, int32(5))
			group := "org.example"
			return client.Page[client.DistinctComponentSummary]{
				Data: []client.DistinctComponentSummary{{
					Name: "openssl", Group: &group, Type: "library",
					PurlTypes: &[]string{"deb", "apk"}, VersionCount: 3, SbomCount: 12,
				}},
				Pagination: client.PaginationMeta{Total: 40},
			}, nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "component", "list",
		"--purl-type", "deb", "--sort", "name", "--sort-dir", "desc", "--limit", "5")
	is.NoErr(err)
	is.Equal(got.PurlType, "deb")
	is.Equal(got.Sort, "name")
	is.Equal(got.SortDir, "desc")

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[1], "org.example/openssl"))
	is.True(strings.Contains(lines[1], "deb,apk"))

	// Counts are guidance, so stderr, and the offset hint appears only when
	// there is actually more to fetch.
	is.True(strings.Contains(stderr, "1 of 40"))
	is.True(strings.Contains(stderr, "--offset 1"))
	is.True(!strings.Contains(stdout, "of 40"))
}

// The plural is what people type; the singular is what the docs say.
func TestComponentsAlias(t *testing.T) {
	is := is.New(t)
	called := false
	fake := &client.FakeClient{
		SearchDistinctComponentsFn: func(context.Context, client.DistinctComponentFilter, client.PageOpts) (client.Page[client.DistinctComponentSummary], error) {
			called = true
			return client.Page[client.DistinctComponentSummary]{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "components", "list")
	is.NoErr(err)
	is.True(called)
}

// The hint is suppressed when the page is the whole result set: a trailing
// "1 of 1" on every single-page listing is noise.
func TestComponentListNoMoreHint(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		SearchDistinctComponentsFn: func(context.Context, client.DistinctComponentFilter, client.PageOpts) (client.Page[client.DistinctComponentSummary], error) {
			return client.Page[client.DistinctComponentSummary]{
				Data:       []client.DistinctComponentSummary{{Name: "curl", Type: "library"}},
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}

	_, stderr, err := runCLI(t, fake, "component", "list")
	is.NoErr(err)
	is.True(strings.Contains(stderr, "1 of 1"))
	is.True(!strings.Contains(stderr, "--offset"))
}

// search is the occurrence view: the name is a positional, not a flag, because
// the server requires it.
func TestComponentSearch(t *testing.T) {
	is := is.New(t)
	var got client.ComponentFilter
	fake := &client.FakeClient{
		SearchComponentsFn: func(_ context.Context, filter client.ComponentFilter, _ client.PageOpts) (client.Page[client.ComponentSummary], error) {
			got = filter
			return client.Page[client.ComponentSummary]{
				Data: []client.ComponentSummary{{
					Id: testComponentID, Name: "openssl", Type: "library",
					Version: ptr("3.0.1"), SbomId: "sbom-1", VulnCount: ptr(int64(2)),
					MaxSeverity: ptr("high"),
				}},
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "component", "search", "openssl", "--version", "3.0.1")
	is.NoErr(err)
	is.Equal(got.Name, "openssl")
	is.Equal(got.Version, "3.0.1")

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[1], "3.0.1"))
	is.True(strings.Contains(lines[1], "high"))
}

func TestComponentSearchRequiresName(t *testing.T) {
	is := is.New(t)
	_, _, err := runCLI(t, &client.FakeClient{}, "component", "search")
	is.True(err != nil)
}

func TestComponentGet(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetComponentFn: func(_ context.Context, id string) (client.ComponentDetail, error) {
			is.Equal(id, testComponentID)
			return client.ComponentDetail{
				Id: id, Name: "openssl", Type: "library", Version: ptr("3.0.1"),
				SbomId: "sbom-1",
				Licenses: &[]client.LicenseSummary{
					{Id: "1", Name: "Apache License 2.0", SpdxId: ptr("Apache-2.0")},
					{Id: "2", Name: "Some Vendor EULA"},
				},
				Hashes: &[]client.HashEntry{{Algorithm: "SHA-256", Value: "abc123"}},
				ExternalReferences: &[]client.ExternalRefEntry{
					{Type: "website", Url: "https://openssl.org"},
				},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "component", "get", testComponentID)
	is.NoErr(err)
	// The three lists are the reason to look a component up, so they must
	// survive rendering rather than being flattened into a cell.
	is.True(strings.Contains(stdout, "license:  Apache-2.0"))
	is.True(strings.Contains(stdout, "license:  Some Vendor EULA"))
	is.True(strings.Contains(stdout, "hash:     SHA-256:abc123"))
	is.True(strings.Contains(stdout, "https://openssl.org"))
}

func TestComponentGetJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetComponentFn: func(_ context.Context, id string) (client.ComponentDetail, error) {
			return client.ComponentDetail{Id: id, Name: "openssl", Type: "library"}, nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "component", "get", testComponentID, "-o", "json")
	is.NoErr(err)
	is.Equal(stderr, "")

	var got client.ComponentDetail
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.Name, "openssl")
}

func TestComponentVersions(t *testing.T) {
	is := is.New(t)
	var got client.GetComponentVersionsParams
	fake := &client.FakeClient{
		GetComponentVersionsFn: func(_ context.Context, params client.GetComponentVersionsParams) (client.GetComponentVersionsOutputBody, error) {
			got = params
			return client.GetComponentVersionsOutputBody{
				Versions: &[]client.ComponentVersionEntry{
					{Version: ptr("1.3"), ArtifactName: ptr("ocidex"), VulnCount: 0},
					{Version: ptr("1.2.13"), ArtifactName: ptr("scanner"), VulnCount: 4, MaxSeverity: ptr("critical")},
				},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "component", "versions", "zlib", "--group", "org.example")
	is.NoErr(err)
	is.Equal(got.Name, "zlib")
	is.Equal(*got.Group, "org.example")
	// Unset flags stay absent rather than filtering on the empty string.
	is.True(got.Version == nil)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 3)
	is.True(strings.Contains(lines[2], "critical"))
}

func TestComponentPurlTypes(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		ListComponentPurlTypesFn: func(context.Context) ([]string, error) {
			return []string{"deb", "golang", "npm"}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "component", "purl-types")
	is.NoErr(err)
	// One per line and nothing else, so the output pipes into xargs.
	is.Equal(stdout, "deb\ngolang\nnpm\n")
}
