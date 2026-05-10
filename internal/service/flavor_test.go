package service

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/matryer/is"
)

func TestDetectFlavor(t *testing.T) {
	tests := []struct {
		name           string
		bom            *cdx.BOM
		subjectVersion string
		want           string
	}{
		{
			name: "alpine-3.19 via syft os:name + version-id",
			bom:  bomWithProps(prop("syft:image:os:name", "alpine"), prop("syft:image:os:version-id", "3.19")),
			want: "alpine-3.19",
		},
		{
			name: "debian-bookworm via syft os:name + version-id",
			bom:  bomWithProps(prop("syft:image:os:name", "debian"), prop("syft:image:os:version-id", "bookworm")),
			want: "debian-bookworm",
		},
		{
			name: "wolfi via syft os:name (no version)",
			bom:  bomWithProps(prop("syft:image:os:name", "wolfi")),
			want: "wolfi",
		},
		{
			name: "os name uppercase is lowercased",
			bom:  bomWithProps(prop("syft:image:os:name", "Alpine"), prop("syft:image:os:version-id", "3.18")),
			want: "alpine-3.18",
		},
		{
			name: "older syft distro:id + distro:version-id",
			bom:  bomWithProps(prop("syft:distro:id", "debian"), prop("syft:distro:version-id", "bullseye")),
			want: "debian-bullseye",
		},
		{
			name: "trivy OS:Family",
			bom:  bomWithProps(prop("aquasecurity:trivy:OS:Family", "alpine")),
			want: "alpine",
		},
		{
			name: "layer1 wins over purls",
			bom: withComponents(
				bomWithProps(prop("syft:image:os:name", "debian")),
				comp("pkg:apk/alpine/busybox@1.36"),
			),
			want: "debian",
		},
		// Layer 2: purl fingerprint
		{
			name: "apk purls no distro qualifier → alpine",
			bom:  withComponents(emptyMeta(), comp("pkg:apk/alpine/busybox@1.36"), comp("pkg:apk/alpine/musl@1.2")),
			want: "alpine",
		},
		{
			name: "apk purls with distro=wolfi-os → wolfi",
			bom:  withComponents(emptyMeta(), comp("pkg:apk/wolfi/curl@8.6?distro=wolfi-os"), comp("pkg:apk/wolfi/busybox@1.36?distro=wolfi-os")),
			want: "wolfi",
		},
		{
			name: "apk purls with distro=chainguard-os → chainguard",
			bom:  withComponents(emptyMeta(), comp("pkg:apk/chainguard/curl@8.6?distro=chainguard-os"), comp("pkg:apk/chainguard/glibc@2.39?distro=chainguard-os")),
			want: "chainguard",
		},
		{
			name: "deb purls with ubuntu namespace → ubuntu",
			bom:  withComponents(emptyMeta(), comp("pkg:deb/ubuntu/curl@7.81?arch=amd64"), comp("pkg:deb/ubuntu/libssl@3.0")),
			want: "ubuntu",
		},
		{
			name: "deb purls with debian namespace → debian",
			bom:  withComponents(emptyMeta(), comp("pkg:deb/debian/curl@7.88"), comp("pkg:deb/debian/libssl@3.0")),
			want: "debian",
		},
		{
			name: "rpm purls with fedora → fedora",
			bom:  withComponents(emptyMeta(), comp("pkg:rpm/fedora/curl@7.85")),
			want: "fedora",
		},
		{
			name: "rpm purls with rhel → rhel",
			bom:  withComponents(emptyMeta(), comp("pkg:rpm/rhel/curl@7.85")),
			want: "rhel",
		},
		{
			name: "rpm purls with centos → rhel",
			bom:  withComponents(emptyMeta(), comp("pkg:rpm/centos/curl@7.85")),
			want: "rhel",
		},
		{
			name: "rpm purls unknown namespace → rpm-other",
			bom:  withComponents(emptyMeta(), comp("pkg:rpm/opensuse/curl@7.85")),
			want: "rpm-other",
		},
		{
			name: "only golang purls → distroless",
			bom:  withComponents(emptyMeta(), comp("pkg:golang/github.com/foo/bar@v1.0"), comp("pkg:golang/github.com/baz/qux@v2.0")),
			want: "distroless",
		},
		{
			name: "empty components → scratch",
			bom:  withComponents(emptyMeta()), // components slice present but empty
			want: "scratch",
		},
		{
			name: "nil components — no layer 2 result, falls through",
			bom:  emptyMeta(),
			want: "unknown", // no version suffix either
		},
		// Layer 3: tag suffix
		{
			name:           "tag suffix -alpine",
			bom:            emptyMeta(),
			subjectVersion: "1.2.3-alpine",
			want:           "alpine",
		},
		{
			name:           "tag suffix -bookworm-slim (longest wins)",
			bom:            emptyMeta(),
			subjectVersion: "app-1.0-bookworm-slim",
			want:           "bookworm-slim",
		},
		{
			name:           "tag suffix -distroless",
			bom:            emptyMeta(),
			subjectVersion: "latest-distroless",
			want:           "distroless",
		},
		{
			name:           "tag suffix case-insensitive",
			bom:            emptyMeta(),
			subjectVersion: "1.0-ALPINE",
			want:           "alpine",
		},
		{
			name:           "no match → unknown",
			bom:            emptyMeta(),
			subjectVersion: "1.2.3",
			want:           "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			got := detectFlavor(tc.bom, tc.subjectVersion)
			is.Equal(got, tc.want)
		})
	}
}

func TestFlavorPURLHelpers(t *testing.T) {
	is := is.New(t)

	is.Equal(purlType("pkg:apk/alpine/busybox@1.36"), "apk")
	is.Equal(purlType("pkg:deb/ubuntu/curl@7.81?arch=amd64"), "deb")
	is.Equal(purlType("pkg:golang/github.com/foo/bar@v1.0"), "golang")
	is.Equal(purlType("notapurl"), "")

	is.Equal(purlNamespace("pkg:deb/ubuntu/curl@7.81"), "ubuntu")
	is.Equal(purlNamespace("pkg:apk/alpine/busybox@1.36"), "alpine")
	is.Equal(purlNamespace("pkg:golang/github.com/foo/bar@v1.0"), "github.com")
	is.Equal(purlNamespace("pkg:rpm/centos/curl@7.85?arch=x86_64"), "centos")

	is.Equal(purlDistroQualifier("pkg:apk/wolfi/curl@8.6?distro=wolfi-os&arch=amd64"), "wolfi-os")
	is.Equal(purlDistroQualifier("pkg:apk/alpine/busybox@1.36"), "")
	is.Equal(purlDistroQualifier("pkg:deb/ubuntu/curl@7.81?arch=amd64&distro=ubuntu-22.04"), "ubuntu-22.04")
}

// --- helpers ---

func prop(name, value string) cdx.Property {
	return cdx.Property{Name: name, Value: value}
}

func comp(purl string) cdx.Component {
	return cdx.Component{PackageURL: purl}
}

func bomWithProps(props ...cdx.Property) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Properties: &props,
		},
	}
	return bom
}

func emptyMeta() *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{},
	}
	return bom
}

func withComponents(bom *cdx.BOM, comps ...cdx.Component) *cdx.BOM {
	bom.Components = &comps
	return bom
}
