package oci

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// ImageRef is an image reference split into its parts. Host is normalized
// (NormalizeRegistryHost); Tag and Digest are "" when the reference carries
// none.
type ImageRef struct {
	Host       string
	Repository string
	Tag        string
	Digest     string
}

// noDefaults stops go-containerregistry from filling in what the reference
// left out. A reference with no registry ("nginx", "library/nginx") keeps an
// empty Host instead of becoming Docker Hub, and one with no tag keeps an
// empty Tag instead of "latest": callers need to know what was actually said.
var noDefaults = []name.Option{name.WithDefaultRegistry(""), name.WithDefaultTag("")}

// ParseImageRef parses an image reference — [host[:port]/]repo[:tag][@digest]
// — with go-containerregistry's parser, which validates every part and tells
// a registry port from a tag. A digest must be a valid
// algorithm:hex digest.
func ParseImageRef(ref string) (ImageRef, error) {
	parsed, err := name.ParseReference(ref, noDefaults...)
	if err != nil {
		return ImageRef{}, fmt.Errorf("parsing image reference %q: %w", ref, err)
	}
	out := ImageRef{
		Host:       NormalizeRegistryHost(parsed.Context().RegistryStr()),
		Repository: parsed.Context().RepositoryStr(),
	}
	switch r := parsed.(type) {
	case name.Tag:
		out.Tag = r.TagStr()
	case name.Digest:
		out.Digest = r.DigestStr()
		// A digest reference keeps only the digest, so a tag written next to
		// it ("app:v1@sha256:...") comes from parsing the part before the "@".
		base, _, _ := strings.Cut(ref, "@")
		if t, err := name.NewTag(base, noDefaults...); err == nil {
			out.Tag = t.TagStr()
		}
	}
	return out, nil
}
