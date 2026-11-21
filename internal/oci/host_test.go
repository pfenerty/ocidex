package oci_test

import (
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/oci"
)

func TestNormalizeRegistryHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"ghcr.io", "ghcr.io"},
		{"https://ghcr.io", "ghcr.io"},
		{"https://ghcr.io/", "ghcr.io"},
		{"ghcr.io/", "ghcr.io"}, // the syft engine used to keep this slash
		{"http://registry.local:5000/", "registry.local:5000"},
		{"registry.local:5000", "registry.local:5000"},
		{"localhost", "localhost"},
		{"localhost:5000", "localhost:5000"},
		{"http://localhost:5000", "localhost:5000"},
		{"docker.io", oci.DockerHubAPIHost},
		{"index.docker.io", oci.DockerHubAPIHost},
		{"hub.docker.com", oci.DockerHubAPIHost},
		{"https://docker.io/", oci.DockerHubAPIHost}, // ocivalidate used to miss this
		{"registry-1.docker.io", oci.DockerHubAPIHost},
		{"GHCR.io", "ghcr.io"},
		{" quay.io ", "quay.io"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			is := is.New(t)
			is.Equal(oci.NormalizeRegistryHost(tt.in), tt.want)
		})
	}
}
