// Package ocivalidate provides a lightweight OCI manifest-type validator.
// It HEADs the registry manifest URL and reports an error when a digest
// points to a manifest list (image index) rather than a single image
// manifest. Built on net/http to keep the API binary free of
// go-containerregistry's remote package.
package ocivalidate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Index media types — a Content-Type match means the digest points at a
// manifest list rather than a single-image manifest.
const (
	mediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// dockerHubHost is the user-visible alias for the Docker Hub registry; the
// actual API lives at registry-1.docker.io (see normalizeRegistryHost).
const dockerHubHost = "docker.io"

// manifestAccept lists every manifest media type the registry might return.
// Without this header some registries default to one type and obscure index
// vs single-image detection.
const manifestAccept = mediaTypeOCIIndex + "," +
	mediaTypeDockerManifestList + "," +
	"application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json"

// Validator HEADs the registry to confirm a digest points to a single image
// manifest. It performs anonymous reads and follows Bearer challenges for
// public images (docker.io, ghcr.io public).
type Validator struct {
	timeout          time.Duration
	insecure         bool
	insecureResolver func(ctx context.Context, host string) bool
	client           *http.Client
}

// Option configures the Validator.
type Option func(*Validator)

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) Option { return func(v *Validator) { v.timeout = d } }

// WithInsecure forces plain HTTP for all hosts.
func WithInsecure() Option { return func(v *Validator) { v.insecure = true } }

// WithInsecureResolver sets a per-host predicate for plain HTTP.
func WithInsecureResolver(fn func(ctx context.Context, host string) bool) Option {
	return func(v *Validator) { v.insecureResolver = fn }
}

// NewValidator returns a Validator configured with opts.
func NewValidator(opts ...Option) *Validator {
	v := &Validator{
		timeout: 30 * time.Second,
		client:  &http.Client{Transport: http.DefaultTransport},
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

func (v *Validator) insecureFor(ctx context.Context, host string) bool {
	if v.insecureResolver != nil && v.insecureResolver(ctx, host) {
		return true
	}
	return v.insecure
}

// ValidateDigest issues HEAD against {imageName}@{digest} and returns an
// error if the digest resolves to a manifest list.
func (v *Validator) ValidateDigest(ctx context.Context, imageName, digest string) error {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	host, repo, err := splitImageName(imageName)
	if err != nil {
		return err
	}
	scheme := "https"
	if v.insecureFor(ctx, host) {
		scheme = "http"
	}
	registryHost := normalizeRegistryHost(host)
	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, registryHost, repo, digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return fmt.Errorf("building HEAD request: %w", err)
	}
	req.Header.Set("Accept", manifestAccept)

	resp, err := v.do(ctx, req)
	if err != nil {
		return fmt.Errorf("HEAD %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HEAD %s: HTTP %d", url, resp.StatusCode)
	}

	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if ct == mediaTypeOCIIndex || ct == mediaTypeDockerManifestList {
		return fmt.Errorf(
			"digest %s is a manifest list (multi-arch image); SBOM must reference a specific platform image manifest, not an image index",
			digest,
		)
	}

	return nil
}

// do performs the request, following a single Bearer challenge if the
// registry returns 401 with WWW-Authenticate. Anonymous-only — the
// previous go-containerregistry-based Validator didn't accept credentials
// either, so private images were already unsupported by ingest validation.
func (v *Validator) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := v.client.Do(req) //nolint:gosec // G704: req.URL is built from imageName, intentionally caller-controlled
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("Www-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") {
		return resp, nil
	}
	realm, svc, scope := parseBearerChallenge(challenge)
	if realm == "" {
		return resp, nil
	}
	resp.Body.Close()

	token, err := v.fetchAnonymousToken(ctx, realm, svc, scope)
	if err != nil {
		return nil, fmt.Errorf("anonymous token exchange: %w", err)
	}

	retry := req.Clone(ctx)
	retry.Header.Set("Authorization", "Bearer "+token)
	return v.client.Do(retry) //nolint:gosec // G704: see comment above
}

func (v *Validator) fetchAnonymousToken(ctx context.Context, realm, svc, scope string) (string, error) {
	u := realm + "?"
	if svc != "" {
		u += "service=" + svc + "&"
	}
	if scope != "" {
		u += "scope=" + scope
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // G704: realm URL comes from registry's WWW-Authenticate header, not arbitrary user input
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req) //nolint:gosec // G704: see comment above
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint HTTP %d", resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	return body.AccessToken, nil
}

// splitImageName splits "host/repo/path" into host and "repo/path".
// A bare "library/alpine" form is rewritten with the docker.io host.
func splitImageName(imageName string) (host, repo string, err error) {
	if imageName == "" {
		return "", "", fmt.Errorf("empty image name")
	}
	slash := strings.Index(imageName, "/")
	if slash == -1 {
		// "alpine" → docker.io official-library shorthand
		return dockerHubHost, "library/" + imageName, nil
	}
	first := imageName[:slash]
	if !strings.ContainsAny(first, ".:") && first != "localhost" {
		// "library/alpine" or "user/repo" — no registry host, assume docker.io
		return dockerHubHost, imageName, nil
	}
	return first, imageName[slash+1:], nil
}

// normalizeRegistryHost rewrites docker.io aliases to the actual API host.
// Mirrors the unexported helper in internal/scanner/catalog.go.
func normalizeRegistryHost(host string) string {
	switch host {
	case "docker.io", "index.docker.io", "hub.docker.com":
		return "registry-1.docker.io"
	}
	return host
}

// parseBearerChallenge extracts realm, service, and scope from
//
//	Bearer realm="...",service="...",scope="..."
func parseBearerChallenge(header string) (realm, svc, scope string) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", "", ""
	}
	for _, part := range strings.Split(header[len("Bearer "):], ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		val := strings.Trim(kv[1], `"`)
		switch strings.TrimSpace(kv[0]) {
		case "realm":
			realm = val
		case "service":
			svc = val
		case "scope":
			scope = val
		}
	}
	return realm, svc, scope
}
