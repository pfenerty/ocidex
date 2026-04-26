package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestHarborDiscoverer(t *testing.T) {
	t.Run("single page with tagged and untagged artifacts", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			is.Equal(r.URL.Path, "/api/v2.0/projects/myproject/repositories/myrepo/artifacts")
			artifacts := []map[string]any{
				{
					"digest":     "sha256:aaa",
					"media_type": "application/vnd.oci.image.manifest.v1+json",
					"tags":       []map[string]any{{"name": "v1.0"}},
					"extra_attrs": map[string]any{
						"architecture": "amd64",
					},
				},
				{
					"digest":     "sha256:bbb",
					"media_type": "application/vnd.oci.image.manifest.v1+json",
					"tags":       []map[string]any{},
					"extra_attrs": map[string]any{},
				},
			}
			_ = json.NewEncoder(w).Encode(artifacts)
		}))
		defer srv.Close()

		d := &harborDiscoverer{}
		manifests, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myproject/myrepo")
		is.NoErr(err)
		is.Equal(len(manifests), 2)
		is.Equal(manifests[0].Digest, "sha256:aaa")
		is.Equal(manifests[0].Tag, "v1.0")
		is.Equal(manifests[0].Arch, "amd64")
		is.Equal(manifests[1].Digest, "sha256:bbb")
		is.Equal(manifests[1].Tag, "")
	})

	t.Run("pagination combines all pages", func(t *testing.T) {
		is := is.New(t)
		callCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			page := r.URL.Query().Get("page")
			if page == "1" {
				// Return full page of 100 artifacts to trigger next page fetch.
				artifacts := make([]map[string]any, 100)
				for i := range artifacts {
					artifacts[i] = map[string]any{
						"digest":     fmt.Sprintf("sha256:%03d", i),
						"media_type": "application/vnd.oci.image.manifest.v1+json",
						"tags":       []map[string]any{},
					}
				}
				_ = json.NewEncoder(w).Encode(artifacts)
			} else {
				artifacts := []map[string]any{
					{"digest": "sha256:page2", "media_type": "application/vnd.oci.image.manifest.v1+json", "tags": []map[string]any{}},
				}
				_ = json.NewEncoder(w).Encode(artifacts)
			}
		}))
		defer srv.Close()

		d := &harborDiscoverer{}
		manifests, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "proj/repo")
		is.NoErr(err)
		is.Equal(len(manifests), 101)
		is.Equal(callCount, 2)
	})

	t.Run("HTTP error returns error", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "server error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		d := &harborDiscoverer{}
		_, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "proj/repo")
		is.True(err != nil)
	})

	t.Run("bad repo format returns error", func(t *testing.T) {
		is := is.New(t)
		d := &harborDiscoverer{}
		_, err := d.DiscoverManifests(t.Context(), &http.Client{}, "http://unused", "noslash")
		is.True(err != nil)
	})

	t.Run("basic auth sent when token configured", func(t *testing.T) {
		is := is.New(t)
		var gotUser, gotPass string
		var gotAuth bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPass, gotAuth = r.BasicAuth()
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}))
		defer srv.Close()

		d := &harborDiscoverer{authToken: "mytoken"} // authUsername empty → default "ocidex"
		_, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "proj/repo")
		is.NoErr(err)
		is.True(gotAuth)
		is.Equal(gotUser, "ocidex")
		is.Equal(gotPass, "mytoken")
	})

	t.Run("custom username used with token", func(t *testing.T) {
		is := is.New(t)
		var gotUser string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, _, _ = r.BasicAuth()
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}))
		defer srv.Close()

		d := &harborDiscoverer{authUsername: "admin", authToken: "mytoken"}
		_, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "proj/repo")
		is.NoErr(err)
		is.Equal(gotUser, "admin")
	})
}

func TestZotDiscoverer(t *testing.T) {
	t.Run("returns manifests from search results", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			is.Equal(r.Method, http.MethodPost)
			is.Equal(r.URL.Path, "/v2/_zot/ext/search")
			resp := map[string]any{
				"data": map[string]any{
					"ImageList": map[string]any{
						"Results": []map[string]any{
							{"Digest": "sha256:aaa", "MediaType": "application/vnd.oci.image.manifest.v1+json", "Tag": "latest"},
							{"Digest": "sha256:bbb", "MediaType": "application/vnd.oci.image.manifest.v1+json", "Tag": "v1.0"},
							{"Digest": "sha256:ccc", "MediaType": "application/vnd.oci.image.manifest.v1+json", "Tag": ""},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		d := &zotDiscoverer{}
		manifests, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myrepo")
		is.NoErr(err)
		is.Equal(len(manifests), 3)
		is.Equal(manifests[0].Digest, "sha256:aaa")
		is.Equal(manifests[0].Tag, "latest")
		is.Equal(manifests[2].Digest, "sha256:ccc")
	})

	t.Run("empty results returns empty slice", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]any{
				"data": map[string]any{
					"ImageList": map[string]any{
						"Results": []map[string]any{},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		d := &zotDiscoverer{}
		manifests, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myrepo")
		is.NoErr(err)
		is.Equal(len(manifests), 0)
	})

	t.Run("404 returns search-unavailable error", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()

		d := &zotDiscoverer{}
		_, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myrepo")
		is.True(err != nil)
	})

	t.Run("400 returns search-unavailable error", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad request", http.StatusBadRequest)
		}))
		defer srv.Close()

		d := &zotDiscoverer{}
		_, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myrepo")
		is.True(err != nil)
	})

	t.Run("non-200 other returns error", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		d := &zotDiscoverer{}
		_, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myrepo")
		is.True(err != nil)
	})

	t.Run("empty digest entries are filtered out", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]any{
				"data": map[string]any{
					"ImageList": map[string]any{
						"Results": []map[string]any{
							{"Digest": "sha256:aaa", "MediaType": "application/vnd.oci.image.manifest.v1+json", "Tag": "v1"},
							{"Digest": "", "MediaType": "application/vnd.oci.image.manifest.v1+json", "Tag": "bad"},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		d := &zotDiscoverer{}
		manifests, err := d.DiscoverManifests(t.Context(), srv.Client(), srv.URL, "myrepo")
		is.NoErr(err)
		is.Equal(len(manifests), 1)
		is.Equal(manifests[0].Digest, "sha256:aaa")
	})
}

func TestSplitHarborRepo(t *testing.T) {
	cases := []struct {
		input           string
		project, repo   string
		ok              bool
	}{
		{"myproject/myrepo", "myproject", "myrepo", true},
		{"myproject/nested/path", "myproject", "nested/path", true},
		{"noslash", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			is := is.New(t)
			proj, repo, ok := splitHarborRepo(tc.input)
			is.Equal(ok, tc.ok)
			is.Equal(proj, tc.project)
			is.Equal(repo, tc.repo)
		})
	}
}

func TestSplitGHCRRepo(t *testing.T) {
	cases := []struct {
		input         string
		owner, name   string
		ok            bool
	}{
		{"owner/name", "owner", "name", true},
		{"owner/nested/name", "owner", "nested/name", true},
		{"noslash", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			is := is.New(t)
			owner, name, ok := splitGHCRRepo(tc.input)
			is.Equal(ok, tc.ok)
			is.Equal(owner, tc.owner)
			is.Equal(name, tc.name)
		})
	}
}

func TestIsImageManifestType(t *testing.T) {
	cases := []struct {
		mt   string
		want bool
	}{
		{"application/vnd.oci.image.manifest.v1+json", true},
		{"application/vnd.docker.distribution.manifest.v2+json", true},
		{"application/vnd.oci.image.index.v1+json", true},
		{"application/vnd.docker.distribution.manifest.list.v2+json", true},
		{"application/vnd.dev.cosign.simplesigning.v1+json", false},
		{"text/plain", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.mt, func(t *testing.T) {
			is := is.New(t)
			is.Equal(isImageManifestType(tc.mt), tc.want)
		})
	}
}

func TestUnknownDiscoverer(t *testing.T) {
	is := is.New(t)
	d := &unknownDiscoverer{typeName: "nosuchregistry"}
	_, err := d.DiscoverManifests(t.Context(), &http.Client{}, "http://unused", "repo")
	is.True(err != nil)
}

func TestDerefStr(t *testing.T) {
	is := is.New(t)
	is.Equal(derefStr(nil), "")
	s := "hello"
	is.Equal(derefStr(&s), "hello")
}

func TestParseNextLink(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "next link present",
			header: `<https://api.example.com/page2>; rel="next", <https://api.example.com/last>; rel="last"`,
			want:   "https://api.example.com/page2",
		},
		{
			name:   "only last link",
			header: `<https://api.example.com/last>; rel="last"`,
			want:   "",
		},
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(parseNextLink(tc.header), tc.want)
		})
	}
}
