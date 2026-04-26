package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

func registryForURL(url string, insecure bool) service.Registry {
	return service.Registry{URL: url, Insecure: insecure}
}

func TestParseWWWAuthenticate(t *testing.T) {
	cases := []struct {
		name          string
		header        string
		realm, svc, scope string
	}{
		{
			name:   "full bearer header",
			header: `Bearer realm="https://auth.example.com/token",service="registry",scope="pull"`,
			realm:  "https://auth.example.com/token",
			svc:    "registry",
			scope:  "pull",
		},
		{
			name:   "realm only",
			header: `Bearer realm="https://auth.example.com/token"`,
			realm:  "https://auth.example.com/token",
			svc:    "",
			scope:  "",
		},
		{
			name:   "not bearer returns empty",
			header: `Basic realm="test"`,
			realm:  "",
			svc:    "",
			scope:  "",
		},
		{
			name:   "empty header returns empty",
			header: "",
			realm:  "",
			svc:    "",
			scope:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			r, s, sc := parseWWWAuthenticate(tc.header)
			is.Equal(r, tc.realm)
			is.Equal(s, tc.svc)
			is.Equal(sc, tc.scope)
		})
	}
}

func TestRegistrySchemeHost(t *testing.T) {
	cases := []struct {
		name           string
		url            string
		insecure       bool
		wantScheme     string
		wantHost       string
	}{
		{
			name: "explicit https",
			url:  "https://registry.example.com",
			wantScheme: "https",
			wantHost:   "registry.example.com",
		},
		{
			name: "explicit http",
			url:  "http://registry.example.com",
			wantScheme: "http",
			wantHost:   "registry.example.com",
		},
		{
			name:     "no scheme insecure",
			url:      "registry.example.com",
			insecure: true,
			wantScheme: "http",
			wantHost:   "registry.example.com",
		},
		{
			name:     "no scheme secure",
			url:      "registry.example.com",
			insecure: false,
			wantScheme: "https",
			wantHost:   "registry.example.com",
		},
		{
			name: "trailing slash stripped",
			url:  "https://registry.example.com/",
			wantScheme: "https",
			wantHost:   "registry.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			reg := registryForURL(tc.url, tc.insecure)
			scheme, host := registrySchemeHost(reg)
			is.Equal(scheme, tc.wantScheme)
			is.Equal(host, tc.wantHost)
		})
	}
}

type fakeLister struct {
	digests map[string]bool
	err     error
}

func (f *fakeLister) ListDigestsByRegistry(_ context.Context, _ string) (map[string]bool, error) {
	return f.digests, f.err
}

func TestFetchKnownDigests(t *testing.T) {
	t.Run("nil lister returns nil", func(t *testing.T) {
		is := is.New(t)
		got := FetchKnownDigests(t.Context(), nil, "registry-id")
		is.True(got == nil)
	})

	t.Run("empty registry ID returns nil", func(t *testing.T) {
		is := is.New(t)
		lister := &fakeLister{digests: map[string]bool{"sha256:abc": true}}
		got := FetchKnownDigests(t.Context(), lister, "")
		is.True(got == nil)
	})

	t.Run("returns digests from lister", func(t *testing.T) {
		is := is.New(t)
		want := map[string]bool{"sha256:abc": true, "sha256:def": true}
		lister := &fakeLister{digests: want}
		got := FetchKnownDigests(t.Context(), lister, "reg-id")
		is.Equal(got, want)
	})

	t.Run("lister error returns nil", func(t *testing.T) {
		is := is.New(t)
		lister := &fakeLister{err: errors.New("db error")}
		got := FetchKnownDigests(t.Context(), lister, "reg-id")
		is.True(got == nil)
	})
}

func TestOCITokenTransport_PassThrough(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := newOCITokenTransport("user", "pass")
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/v2/repo/tags/list") //nolint:noctx
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)
}

func TestOCITokenTransport_BearerAuth(t *testing.T) {
	is := is.New(t)

	var srv *httptest.Server
	requestCount := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "mytoken"})
			return
		}
		requestCount++
		auth := r.Header.Get("Authorization")
		if auth == "" {
			realm := srv.URL + "/token"
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+realm+`",service="testreg",scope="pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		is.Equal(auth, "Bearer mytoken")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := newOCITokenTransport("user", "pass")
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/v2/repo/tags/list") //nolint:noctx
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)
	is.Equal(requestCount, 2) // initial 401 + authenticated retry
}

// TestOCITokenTransport_BearerAuth_AccessToken verifies that the transport handles
// token endpoints that return "access_token" instead of "token".
func TestOCITokenTransport_BearerAuth_AccessToken(t *testing.T) {
	is := is.New(t)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			// Use "access_token" field (e.g. Docker Hub style).
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "accesstoken"})
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			realm := srv.URL + "/token"
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+realm+`",service="testreg",scope="pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		is.Equal(auth, "Bearer accesstoken")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := newOCITokenTransport("user", "pass")
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/v2/repo") //nolint:noctx
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)
}

func TestOCITokenTransport_BasicAuth(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Www-Authenticate", `Basic realm="testreg"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		u, p, ok := r.BasicAuth()
		is.True(ok)
		is.Equal(u, "myuser")
		is.Equal(p, "mypass")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := newOCITokenTransport("myuser", "mypass")
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/v2/repo/tags/list") //nolint:noctx
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)
}

// TestOCITokenTransport_BasicAuth_Anonymous verifies that a Basic auth challenge
// is returned as-is (401) when the transport has no credentials configured.
func TestOCITokenTransport_BasicAuth_Anonymous(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Basic realm="testreg"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	transport := newOCITokenTransport("", "") // anonymous — no credentials
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/v2/repo") //nolint:noctx
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusUnauthorized)
}

func TestOCITokenTransport_UnknownChallenge(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", "Digest realm=test")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	transport := newOCITokenTransport("user", "pass")
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/test") //nolint:noctx
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusUnauthorized)
}
