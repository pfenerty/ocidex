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

const testSBOMID = "33333333-3333-3333-3333-333333333333"

func testSBOMSummary() client.SBOMSummary {
	version, flavor, arch := "v1.2.3", "distroless", "amd64"
	count := int64(412)
	return client.SBOMSummary{
		Id:             testSBOMID,
		SubjectVersion: &version,
		Flavor:         &flavor,
		Architecture:   &arch,
		ComponentCount: &count,
		Sufficient:     true,
		SpecVersion:    "1.5",
		Version:        1,
		CreatedAt:      time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC),
	}
}

func TestSBOMList(t *testing.T) {
	is := is.New(t)
	var got client.SBOMFilter
	fake := &client.FakeClient{
		ListSBOMsFn: func(_ context.Context, filter client.SBOMFilter, opts client.PageOpts) (client.CursorPage[client.SBOMSummary], error) {
			got = filter
			is.Equal(opts.Limit, int32(2))
			return client.CursorPage[client.SBOMSummary]{
				Data: []client.SBOMSummary{testSBOMSummary()},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "sbom", "list", "--digest", "sha256:abc", "--limit", "2")
	is.NoErr(err)
	is.Equal(got.Digest, "sha256:abc")
	is.Equal(got.SerialNumber, "")

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[0], "COMPONENTS"))
	is.True(strings.Contains(lines[1], "v1.2.3"))
	is.True(strings.Contains(lines[1], "412"))
}

// The "more available" hint is a human aid: stderr, table mode only.
func TestSBOMListHasMoreGoesToStderr(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		ListSBOMsFn: func(context.Context, client.SBOMFilter, client.PageOpts) (client.CursorPage[client.SBOMSummary], error) {
			return client.CursorPage[client.SBOMSummary]{
				Data:       []client.SBOMSummary{testSBOMSummary()},
				Pagination: client.CursorMeta{HasMore: true},
			}, nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "sbom", "list")
	is.NoErr(err)
	is.True(strings.Contains(stderr, "more available"))
	is.True(!strings.Contains(stdout, "more available"))
}

func TestSBOMGet(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSBOMFn: func(_ context.Context, id string, includeRaw bool) (client.SBOMDetail, error) {
			is.Equal(id, testSBOMID)
			is.Equal(includeRaw, false)
			return client.SBOMDetail{Id: id, SpecVersion: "1.5", PackageCount: 412}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "sbom", "get", testSBOMID, "-o", "json")
	is.NoErr(err)

	var got client.SBOMDetail
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.PackageCount, int64(412))
}

// --raw prints the stored document itself, so it can be piped into another
// SBOM tool without OCIDex's summary wrapped around it.
func TestSBOMGetRaw(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSBOMFn: func(_ context.Context, _ string, includeRaw bool) (client.SBOMDetail, error) {
			is.Equal(includeRaw, true)
			return client.SBOMDetail{
				Id:     testSBOMID,
				RawBom: map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5"},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "sbom", "get", testSBOMID, "--raw")
	is.NoErr(err)

	var got map[string]any
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got["bomFormat"], "CycloneDX")
	// The summary fields must not be mixed into the document.
	_, hasID := got["id"]
	is.True(!hasID)
}

func TestSBOMGetRawMissing(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSBOMFn: func(context.Context, string, bool) (client.SBOMDetail, error) {
			return client.SBOMDetail{Id: testSBOMID}, nil
		},
	}

	_, _, err := runCLI(t, fake, "sbom", "get", testSBOMID, "--raw")
	is.True(err != nil)
}

func TestSBOMDelete(t *testing.T) {
	is := is.New(t)
	deleted := ""
	fake := &client.FakeClient{
		DeleteSBOMFn: func(_ context.Context, id string) error {
			deleted = id
			return nil
		},
	}

	_, _, err := runCLI(t, fake, "sbom", "delete", testSBOMID, "--yes")
	is.NoErr(err)
	is.Equal(deleted, testSBOMID)
}

func TestSBOMDeleteWithoutConfirmation(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		DeleteSBOMFn: func(context.Context, string) error {
			t.Fatal("delete must not run unconfirmed")
			return nil
		},
	}

	_, _, err := runCLI(t, fake, "sbom", "delete", testSBOMID)
	is.True(err != nil)
}

// push keeps its name; ingest is accepted because the endpoint and the issue
// both use that word.
func TestSBOMIngestAlias(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{}
	// No file argument: the alias is resolved if this is an argument error
	// rather than "unknown command".
	_, _, err := runCLI(t, fake, "sbom", "ingest")
	is.True(err != nil)
	is.True(!strings.Contains(err.Error(), "unknown command"))
}
