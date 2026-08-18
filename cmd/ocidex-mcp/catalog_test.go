package main

import (
	"context"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

func strptr(s string) *string { return &s }

func int64ptr(v int64) *int64 { return &v }

// The unique case: a name resolves to one artifact and the model gets the id
// it needs for every id-taking tool.
func TestLookupArtifactUnique(t *testing.T) {
	i := is.New(t)
	var got client.LookupArtifactParams
	api := &client.FakeClient{
		LookupArtifactFn: func(_ context.Context, params client.LookupArtifactParams) (client.ArtifactDetail, error) {
			got = params
			return client.ArtifactDetail{
				Id:            "a1111111-1111-1111-1111-111111111111",
				Name:          "ghcr.io/pfenerty/ocidex",
				Type:          "container",
				Group:         strptr("pfenerty"),
				SbomCount:     3,
				VersionCount:  2,
				SigningStatus: "verified",
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_artifact", map[string]any{
		"name": "ghcr.io/pfenerty/ocidex",
		"type": "container",
	})
	i.True(!res.IsError)

	// Optional arguments must reach the client as set pointers, and omitted ones
	// as nil — sending group="" would narrow the query to artifacts with an empty
	// group rather than leaving it unnarrowed.
	i.Equal(got.Name, "ghcr.io/pfenerty/ocidex")
	i.Equal(*got.Type, "container")
	i.True(got.Group == nil)

	text := resultText(res)
	i.True(strings.Contains(text, "a1111111-1111-1111-1111-111111111111"))
	i.True(strings.Contains(text, "verified"))
}

// The not-found case has to read as "nothing visible matched", including the
// possibility that it exists but this key cannot see it — an agent that reads
// 404 as "does not exist" will confidently report the wrong thing.
func TestLookupArtifactNotFound(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		LookupArtifactFn: func(context.Context, client.LookupArtifactParams) (client.ArtifactDetail, error) {
			return client.ArtifactDetail{}, client.ErrNotFound
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_artifact", map[string]any{"name": "nope"})
	i.True(res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "nope"))
	i.True(strings.Contains(text, "cannot see"))
}

// The ambiguous case is the one the ADR-042 ladder exists for: the candidate
// list must arrive in a form the model can pick from and retry with.
func TestLookupArtifactAmbiguousListsCandidates(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		LookupArtifactFn: func(context.Context, client.LookupArtifactParams) (client.ArtifactDetail, error) {
			return client.ArtifactDetail{}, &client.ConflictError{
				Detail: "multiple artifacts match",
				Candidates: []client.LookupCandidate{
					{Id: "a1", Qualifiers: map[string]string{"type": "container"}},
					{Id: "a2", Qualifiers: map[string]string{"type": "application"}},
				},
			}
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_artifact", map[string]any{"name": "ocidex"})
	i.True(res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "2 candidates"))
	i.True(strings.Contains(text, "id=a1 (type=container)"))
	i.True(strings.Contains(text, "id=a2 (type=application)"))
	i.True(strings.Contains(text, "one more qualifier"))
}

func TestGetArtifactByID(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetArtifactFn: func(_ context.Context, id string) (client.ArtifactDetail, error) {
			i.Equal(id, "a1111111-1111-1111-1111-111111111111")
			return client.ArtifactDetail{Id: id, Name: "ghcr.io/pfenerty/ocidex", Type: "container"}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_get_artifact", map[string]any{
		"id": "a1111111-1111-1111-1111-111111111111",
	})
	i.True(!res.IsError)
	i.True(strings.Contains(resultText(res), "ghcr.io/pfenerty/ocidex"))
}

func TestLookupSBOMByNameAndVersion(t *testing.T) {
	i := is.New(t)
	var got client.LookupSbomParams
	api := &client.FakeClient{
		LookupSBOMFn: func(_ context.Context, params client.LookupSbomParams) (client.SBOMDetail, error) {
			got = params
			return client.SBOMDetail{
				Id:             "5b011111-1111-1111-1111-111111111111",
				ArtifactId:     strptr("a1"),
				ImageVersion:   strptr("1.2.3"),
				Architecture:   strptr("amd64"),
				Digest:         strptr("sha256:abc"),
				ComponentCount: int64ptr(42),
				PackageCount:   40,
				SpecVersion:    "1.5",
				SigningStatus:  "verified",
				Sufficient:     true,
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_sbom", map[string]any{
		"artifact": "ghcr.io/pfenerty/ocidex",
		"version":  "1.2.3",
		"arch":     "amd64",
	})
	i.True(!res.IsError)
	i.Equal(*got.Artifact, "ghcr.io/pfenerty/ocidex")
	i.Equal(*got.Version, "1.2.3")
	i.Equal(*got.Arch, "amd64")
	i.True(got.Flavor == nil)
	i.True(got.Digest == nil)
	i.True(strings.Contains(resultText(res), "sha256:abc"))
}

// Under-qualified name lookups are the common ADR-042 conflict: one SBOM per
// architecture, so the message has to name arch as the next rung.
func TestLookupSBOMAmbiguousAcrossArchitectures(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		LookupSBOMFn: func(context.Context, client.LookupSbomParams) (client.SBOMDetail, error) {
			return client.SBOMDetail{}, &client.ConflictError{
				Detail: "multiple SBOMs match",
				Candidates: []client.LookupCandidate{
					{Id: "s1", Qualifiers: map[string]string{"arch": "amd64", "flavor": "alpine"}},
					{Id: "s2", Qualifiers: map[string]string{"arch": "arm64", "flavor": "alpine"}},
				},
			}
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_sbom", map[string]any{
		"artifact": "ghcr.io/pfenerty/ocidex",
		"version":  "1.2.3",
	})
	i.True(res.IsError)
	text := resultText(res)
	// The action names the query, so a candidate list is attached to the question
	// that produced it.
	i.True(strings.Contains(text, "ghcr.io/pfenerty/ocidex version 1.2.3"))
	i.True(strings.Contains(text, "id=s1 (arch=amd64, flavor=alpine)"))
}

// Rejecting an impossible query locally beats a 400 round trip that would name
// neither of the two ways to identify an SBOM.
func TestLookupSBOMRequiresDigestOrArtifactAndVersion(t *testing.T) {
	i := is.New(t)
	var called bool
	api := &client.FakeClient{
		LookupSBOMFn: func(context.Context, client.LookupSbomParams) (client.SBOMDetail, error) {
			called = true
			return client.SBOMDetail{}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_sbom", map[string]any{
		"artifact": "ghcr.io/pfenerty/ocidex",
	})
	i.True(res.IsError)
	i.True(!called)
	i.True(strings.Contains(resultText(res), "either digest, or both artifact and version"))
}

func TestLookupLicense(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		LookupLicenseFn: func(_ context.Context, spdxID string) (client.LicenseCount, error) {
			i.Equal(spdxID, "Apache-2.0")
			return client.LicenseCount{
				Id:             "1111",
				SpdxId:         strptr("Apache-2.0"),
				Name:           "Apache License 2.0",
				Category:       "permissive",
				ComponentCount: 128,
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_license", map[string]any{"spdx_id": "Apache-2.0"})
	i.True(!res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "Apache License 2.0"))
	i.True(strings.Contains(text, "128"))
}

func TestLookupLicenseNotFound(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		LookupLicenseFn: func(context.Context, string) (client.LicenseCount, error) {
			return client.LicenseCount{}, client.ErrNotFound
		},
	}

	res := callTool(t, connect(t, api), "ocidex_lookup_license", map[string]any{"spdx_id": "Nonsense-1.0"})
	i.True(res.IsError)
	i.True(strings.Contains(resultText(res), "Nonsense-1.0"))
}

func TestSearchComponents(t *testing.T) {
	i := is.New(t)
	var (
		gotFilter client.ComponentFilter
		gotOpts   client.PageOpts
	)
	api := &client.FakeClient{
		SearchComponentsFn: func(_ context.Context, filter client.ComponentFilter, opts client.PageOpts) (client.Page[client.ComponentSummary], error) {
			gotFilter, gotOpts = filter, opts
			return client.Page[client.ComponentSummary]{
				Data: []client.ComponentSummary{{
					Id:          "c1",
					Name:        "openssl",
					Version:     strptr("3.0.1"),
					Purl:        strptr("pkg:apk/alpine/openssl@3.0.1"),
					Type:        "library",
					SbomId:      "s1",
					IsDirect:    true,
					VulnCount:   int64ptr(2),
					MaxSeverity: strptr("high"),
				}},
				Pagination: client.PaginationMeta{Total: 1, Limit: 50},
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_search_components", map[string]any{"name": "openssl"})
	i.True(!res.IsError)
	i.Equal(gotFilter.Name, "openssl")
	// An omitted limit becomes the documented default rather than the client's
	// zero, so the tool's description and its behaviour agree.
	i.Equal(gotOpts.Limit, int32(defaultSearchLimit))

	text := resultText(res)
	i.True(strings.Contains(text, "pkg:apk/alpine/openssl@3.0.1"))
	i.True(strings.Contains(text, "high"))
}

// An empty page is a legitimate answer, not an error: the model needs to see
// zero rows and a zero total rather than a failure it might retry.
func TestSearchComponentsEmptyIsNotAnError(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		SearchComponentsFn: func(context.Context, client.ComponentFilter, client.PageOpts) (client.Page[client.ComponentSummary], error) {
			return client.Page[client.ComponentSummary]{}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_search_components", map[string]any{"purl": "pkg:apk/alpine/nope@1"})
	i.True(!res.IsError)
	i.True(strings.Contains(resultText(res), `"components":[]`))
}

func TestSearchComponentsRequiresNameOrPurl(t *testing.T) {
	i := is.New(t)
	var called bool
	api := &client.FakeClient{
		SearchComponentsFn: func(context.Context, client.ComponentFilter, client.PageOpts) (client.Page[client.ComponentSummary], error) {
			called = true
			return client.Page[client.ComponentSummary]{}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_search_components", map[string]any{"group": "org.example"})
	i.True(res.IsError)
	i.True(!called)
	i.True(strings.Contains(resultText(res), "either name or purl"))
}

func TestListNamespaces(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListNamespacesFn: func(context.Context) ([]client.NamespaceResponse, error) {
			return []client.NamespaceResponse{{
				Id:            "n1",
				Name:          "pfenerty",
				Visibility:    "public",
				OwnerUsername: strptr("octocat"),
			}}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_list_namespaces", nil)
	i.True(!res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "pfenerty"))
	i.True(strings.Contains(text, "public"))
}

func TestListNamespacesSurfacesForbidden(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListNamespacesFn: func(context.Context) ([]client.NamespaceResponse, error) {
			return nil, client.ErrForbidden
		},
	}

	res := callTool(t, connect(t, api), "ocidex_list_namespaces", nil)
	i.True(res.IsError)
	i.True(strings.Contains(resultText(res), "read-write"))
}
