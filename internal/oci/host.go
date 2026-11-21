// Package oci holds the rules for naming things in an OCI registry: registry
// hosts and image references. It imports nothing from this module, so every
// package that matches or contacts a registry can share one definition.
package oci

import "strings"

// DockerHubAPIHost is the host that actually serves the Docker Hub registry
// API. docker.io, index.docker.io and hub.docker.com are aliases for it; the
// first and last answer the web frontend, not the API.
const DockerHubAPIHost = "registry-1.docker.io"

// NormalizeRegistryHost reduces a registry URL or host to the comparable host
// that serves its API: it drops any scheme ("https://") and trailing slash,
// lowercases the host, and maps the Docker Hub aliases onto DockerHubAPIHost.
// A port is kept, since it names a different endpoint.
//
// Every place that matches a registry's configured URL against an image's
// host, or builds a URL to contact one, uses this, so a registry configured as
// "https://ghcr.io/" names the same host everywhere.
func NormalizeRegistryHost(host string) string {
	host = strings.TrimSpace(host)
	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}
	host = strings.ToLower(strings.TrimRight(host, "/"))
	switch host {
	case "docker.io", "index.docker.io", "hub.docker.com":
		return DockerHubAPIHost
	}
	return host
}
