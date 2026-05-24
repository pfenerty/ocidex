package ocivalidate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestValidator_ValidateDigest(t *testing.T) {
	const digest = "sha256:abc123"
	const repo = "library/alpine"

	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{
			name:        "OCI single-image manifest passes",
			contentType: "application/vnd.oci.image.manifest.v1+json",
			wantErr:     false,
		},
		{
			name:        "Docker schema-2 single-image manifest passes",
			contentType: "application/vnd.docker.distribution.manifest.v2+json",
			wantErr:     false,
		},
		{
			name:        "OCI index is rejected",
			contentType: "application/vnd.oci.image.index.v1+json",
			wantErr:     true,
		},
		{
			name:        "Docker manifest list is rejected",
			contentType: "application/vnd.docker.distribution.manifest.list.v2+json",
			wantErr:     true,
		},
		{
			name:        "Content-Type with charset suffix is still parsed",
			contentType: "application/vnd.oci.image.index.v1+json; charset=utf-8",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead {
					t.Errorf("expected HEAD, got %s", r.Method)
				}
				if !strings.HasSuffix(r.URL.Path, "/v2/"+repo+"/manifests/"+digest) {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			host := strings.TrimPrefix(srv.URL, "http://")
			v := NewValidator(WithInsecureResolver(func(_ context.Context, h string) bool { return h == host }))

			err := v.ValidateDigest(context.Background(), host+"/"+repo, digest)
			if tt.wantErr {
				is.True(err != nil)
			} else {
				is.NoErr(err)
			}
		})
	}
}

func TestValidator_FollowsBearerChallenge(t *testing.T) {
	is := is.New(t)
	const digest = "sha256:def456"
	const repo = "library/nginx"

	var (
		tokenServerHits    int
		manifestServerHits int
	)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenServerHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"deadbeef"}`))
	}))
	defer tokenSrv.Close()

	manifestSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestServerHits++
		auth := r.Header.Get("Authorization")
		if auth != "Bearer deadbeef" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+tokenSrv.URL+`",service="registry",scope="repository:`+repo+`:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.WriteHeader(http.StatusOK)
	}))
	defer manifestSrv.Close()

	host := strings.TrimPrefix(manifestSrv.URL, "http://")
	v := NewValidator(WithInsecureResolver(func(_ context.Context, h string) bool { return h == host }))

	err := v.ValidateDigest(context.Background(), host+"/"+repo, digest)
	is.NoErr(err)
	is.Equal(tokenServerHits, 1)
	is.Equal(manifestServerHits, 2) // first 401, second 200
}

func TestSplitImageName(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantRepo string
	}{
		{"alpine", "docker.io", "library/alpine"},
		{"library/alpine", "docker.io", "library/alpine"},
		{"nginx/nginx", "docker.io", "nginx/nginx"},
		{"ghcr.io/owner/repo", "ghcr.io", "owner/repo"},
		{"quay.io/org/image", "quay.io", "org/image"},
		{"localhost:5000/myrepo", "localhost:5000", "myrepo"},
		{"zot:5000/library/img", "zot:5000", "library/img"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			is := is.New(t)
			host, repo, err := splitImageName(tt.in)
			is.NoErr(err)
			is.Equal(host, tt.wantHost)
			is.Equal(repo, tt.wantRepo)
		})
	}
}
