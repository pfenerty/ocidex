package oci_test

import (
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/oci"
)

var testDigest = "sha256:" + strings.Repeat("a", 64)

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		ref  string
		want oci.ImageRef
	}{
		{"ghcr.io/pfenerty/api:v1.2.3", oci.ImageRef{Host: "ghcr.io", Repository: "pfenerty/api", Tag: "v1.2.3"}},
		{"ghcr.io/pfenerty/api@" + testDigest, oci.ImageRef{Host: "ghcr.io", Repository: "pfenerty/api", Digest: testDigest}},
		{"quay.io/team/app:v1@" + testDigest, oci.ImageRef{Host: "quay.io", Repository: "team/app", Tag: "v1", Digest: testDigest}},
		{"registry.local:5000/team/app:v1@" + testDigest, oci.ImageRef{Host: "registry.local:5000", Repository: "team/app", Tag: "v1", Digest: testDigest}},
		{"localhost:5005/ocidex", oci.ImageRef{Host: "localhost:5005", Repository: "ocidex"}},
		{"localhost/ocidex:dev", oci.ImageRef{Host: "localhost", Repository: "ocidex", Tag: "dev"}},
		{"docker.io/library/nginx:1.27", oci.ImageRef{Host: oci.DockerHubAPIHost, Repository: "library/nginx", Tag: "1.27"}},
		{"registry.example.com/a/b/c/app", oci.ImageRef{Host: "registry.example.com", Repository: "a/b/c/app"}},
		// No registry: no host, and no "library/" guessed either.
		{"nginx", oci.ImageRef{Repository: "nginx"}},
		{"library/nginx:1.27", oci.ImageRef{Repository: "library/nginx", Tag: "1.27"}},
		{"nginx@" + testDigest, oci.ImageRef{Repository: "nginx", Digest: testDigest}},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			is := is.New(t)
			got, err := oci.ParseImageRef(tt.ref)
			is.NoErr(err)
			is.Equal(got, tt.want)
		})
	}
}

func TestParseImageRefInvalid(t *testing.T) {
	for _, ref := range []string{
		"",
		"ghcr.io/pfenerty/api@sha256:abc", // a digest must be full length
		"ghcr.io/pfenerty/api:",           // empty tag
		"https://ghcr.io/pfenerty/api",    // a scheme is not part of a reference
		"ghcr.io/Pfenerty/API",            // repositories are lowercase
		"ghcr.io/a@" + testDigest + "@" + testDigest,
	} {
		t.Run(ref, func(t *testing.T) {
			_, err := oci.ParseImageRef(ref)
			if err == nil {
				t.Errorf("ParseImageRef(%q) succeeded, want an error", ref)
			}
		})
	}
}
