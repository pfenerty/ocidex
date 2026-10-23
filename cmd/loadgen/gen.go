package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Spec sizes a synthetic corpus: Artifacts artifacts, each with Versions
// versions of about Components components. Every artifact sits on one of
// BaseImages shared base images, whose OS packages make up BaseShare of its
// components; the rest are its own language libraries. Between consecutive
// versions a Churn fraction of components change version.
type Spec struct {
	Seed       uint64
	Artifacts  int
	Versions   int
	Components int
	BaseImages int
	BaseShare  float64
	Churn      float64
}

// SBOM is one generated document and the subject facts the ingest API takes
// beside it.
type SBOM struct {
	Artifact string
	Version  string
	Digest   string
	Doc      []byte
}

type osFamily struct {
	name, purlType, namespace string
	// real packages at versions with published advisories, so vulnerability
	// matching has something to find
	vulnerable [][2]string
}

var osFamilies = []osFamily{
	{name: "alpine", purlType: "apk", namespace: "alpine", vulnerable: [][2]string{
		{"openssl", "3.0.7-r0"}, {"libcrypto3", "3.0.7-r0"}, {"busybox", "1.36.0-r0"},
		{"zlib", "1.2.13-r0"}, {"curl", "8.0.1-r0"}, {"expat", "2.5.0-r0"},
	}},
	{name: "debian", purlType: "deb", namespace: "debian", vulnerable: [][2]string{
		{"openssl", "3.0.9-1"}, {"libssl3", "3.0.9-1"}, {"curl", "7.88.1-10"},
		{"zlib1g", "1:1.2.13.dfsg-1"}, {"libc6", "2.36-9"}, {"tar", "1.34+dfsg-1.2"},
	}},
}

type language struct {
	purlType   string
	vulnerable [][2]string
	name       func(i int) string
}

var languages = []language{
	{purlType: "golang", vulnerable: [][2]string{
		{"golang.org/x/net", "v0.7.0"}, {"github.com/gin-gonic/gin", "v1.9.0"},
		{"golang.org/x/crypto", "v0.14.0"}, {"google.golang.org/grpc", "v1.56.2"},
	}, name: func(i int) string { return fmt.Sprintf("github.com/loadgen/mod-%04d", i) }},
	{purlType: "npm", vulnerable: [][2]string{
		{"lodash", "4.17.20"}, {"axios", "1.5.1"}, {"semver", "7.5.1"}, {"express", "4.18.2"},
	}, name: func(i int) string { return fmt.Sprintf("loadgen-pkg-%04d", i) }},
	{purlType: "pypi", vulnerable: [][2]string{
		{"requests", "2.30.0"}, {"urllib3", "2.0.6"}, {"jinja2", "3.1.2"}, {"pillow", "10.0.0"},
	}, name: func(i int) string { return fmt.Sprintf("loadgen-dist-%04d", i) }},
}

var licenses = []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0", "GPL-2.0-only"}

// pkg is one component slot: a fixed name and an evolving version.
type pkg struct {
	purlType, namespace, name string
	base                      string // the vulnerable starting version, or "" for synthetic
	bump                      int
	license                   string
	deps                      []int
}

func (p pkg) version() string {
	if p.base != "" {
		if p.bump == 0 {
			return p.base
		}
		return fmt.Sprintf("%s.%d", p.base, p.bump)
	}
	return fmt.Sprintf("1.%d.%d", p.bump/10, p.bump%10)
}

func (p pkg) purl() string {
	ns := ""
	if p.namespace != "" {
		ns = p.namespace + "/"
	}
	return fmt.Sprintf("pkg:%s/%s%s@%s", p.purlType, ns, p.name, p.version())
}

// Generate calls emit for every SBOM in the corpus, artifact by artifact and
// oldest version first. The same Spec always yields the same bytes.
func Generate(spec Spec, emit func(SBOM) error) error {
	bases := make([][]pkg, spec.BaseImages)
	baseSize := int(float64(spec.Components) * spec.BaseShare)
	for b := range bases {
		bases[b] = basePackages(spec.Seed, b, baseSize)
	}
	for a := range spec.Artifacts {
		r := rand.New(rand.NewPCG(spec.Seed, uint64(a)+1)) //nolint:gosec // G404: synthetic data, not security
		base := bases[a%len(bases)]
		pkgs := append(clonePkgs(base), appPackages(r, a, spec.Components-len(base))...)
		linkDependencies(r, pkgs, len(base))
		name := fmt.Sprintf("loadgen.test/%s-app-%03d", languages[a%len(languages)].purlType, a)
		for v := range spec.Versions {
			s, err := document(spec.Seed, name, a, v, pkgs)
			if err != nil {
				return err
			}
			if err := emit(s); err != nil {
				return err
			}
			churn(r, pkgs, spec.Churn)
		}
	}
	return nil
}

// basePackages is base image b's OS packages: the family's vulnerable real
// packages, then synthetic ones up to n.
func basePackages(seed uint64, b, n int) []pkg {
	r := rand.New(rand.NewPCG(seed, 1<<32+uint64(b))) //nolint:gosec // G404: synthetic data
	fam := osFamilies[b%len(osFamilies)]
	out := make([]pkg, 0, n)
	for _, v := range fam.vulnerable {
		if len(out) == n {
			break
		}
		out = append(out, pkg{purlType: fam.purlType, namespace: fam.namespace, name: v[0], base: v[1], license: pick(r, licenses)})
	}
	for i := len(out); i < n; i++ {
		out = append(out, pkg{purlType: fam.purlType, namespace: fam.namespace,
			name: fmt.Sprintf("%s-base%d-lib%03d", fam.name, b, i), bump: r.IntN(50), license: pick(r, licenses)})
	}
	return out
}

// appPackages is artifact a's own n language libraries.
func appPackages(r *rand.Rand, a, n int) []pkg {
	lang := languages[a%len(languages)]
	out := make([]pkg, 0, max(n, 0))
	for _, v := range lang.vulnerable {
		if len(out) >= n {
			break
		}
		out = append(out, pkg{purlType: lang.purlType, name: v[0], base: v[1], license: pick(r, licenses)})
	}
	for i := len(out); i < n; i++ {
		out = append(out, pkg{purlType: lang.purlType, name: lang.name(a*10000 + i), bump: r.IntN(50), license: pick(r, licenses)})
	}
	return out
}

// linkDependencies gives each application library one to three dependencies on
// earlier components, base packages included, so the graph has depth and
// reaches the OS layer.
func linkDependencies(r *rand.Rand, pkgs []pkg, firstApp int) {
	for i := max(firstApp, 1); i < len(pkgs); i++ {
		n := 1 + r.IntN(3)
		for range n {
			pkgs[i].deps = append(pkgs[i].deps, r.IntN(i))
		}
	}
}

// churn bumps the version of a fraction of components, as a release would.
func churn(r *rand.Rand, pkgs []pkg, fraction float64) {
	for i := range pkgs {
		if r.Float64() < fraction {
			pkgs[i].bump++
		}
	}
}

func clonePkgs(in []pkg) []pkg {
	out := make([]pkg, len(in))
	copy(out, in)
	return out
}

func pick(r *rand.Rand, from []string) string { return from[r.IntN(len(from))] }

// document renders one CycloneDX 1.6 SBOM of artifact a at version v.
func document(seed uint64, name string, a, v int, pkgs []pkg) (SBOM, error) {
	sum := sha256.Sum256(fmt.Appendf(nil, "loadgen/%d/%d/%d", seed, a, v))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	version := fmt.Sprintf("v1.%d.0", v)
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(v) * 24 * time.Hour)

	comps := make([]cdx.Component, len(pkgs))
	deps := make([]cdx.Dependency, 0, len(pkgs)+1)
	rootDeps := make([]string, 0, len(pkgs))
	for i, p := range pkgs {
		ref := fmt.Sprintf("c%d", i)
		comps[i] = cdx.Component{
			BOMRef: ref, Type: cdx.ComponentTypeLibrary, Name: p.name, Version: p.version(), PackageURL: p.purl(),
			Licenses: &cdx.Licenses{{License: &cdx.License{ID: p.license}}},
		}
		if len(p.deps) > 0 {
			on := make([]string, len(p.deps))
			for j, d := range p.deps {
				on[j] = fmt.Sprintf("c%d", d)
			}
			deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: &on})
		} else {
			rootDeps = append(rootDeps, ref)
		}
	}
	deps = append(deps, cdx.Dependency{Ref: "root", Dependencies: &rootDeps})

	doc := cdx.BOM{
		BOMFormat:    cdx.BOMFormat,
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]),
		Version:      1,
		Metadata: &cdx.Metadata{Component: &cdx.Component{
			// No "@sha256:" in the name: ingest would then check the digest
			// against the (unreachable) registry. The digest goes beside the
			// document instead, as the ingest API's digest parameter.
			BOMRef: "root", Type: cdx.ComponentTypeContainer, Name: name, Version: version,
			Properties: &[]cdx.Property{
				{Name: "syft:image:labels:org.opencontainers.image.architecture", Value: "amd64"},
				{Name: "syft:image:labels:org.opencontainers.image.created", Value: created.Format(time.RFC3339)},
			},
		}},
		Components:   &comps,
		Dependencies: &deps,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return SBOM{}, fmt.Errorf("encoding %s %s: %w", name, version, err)
	}
	return SBOM{Artifact: name, Version: version, Digest: digest, Doc: b}, nil
}
