package service

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// detectFlavor returns the image flavor for an SBOM using a 3-layer detector.
// Never returns an empty string — falls back to "unknown".
func detectFlavor(bom *cdx.BOM, subjectVersion string) string {
	if f := flavorFromOSMetadata(bom); f != "" {
		return f
	}
	if f := flavorFromPURLs(bom); f != "" {
		return f
	}
	if f := flavorFromTagSuffix(subjectVersion); f != "" {
		return f
	}
	return "unknown"
}

// --- Layer 1: OS metadata properties ---

// osNameKeys are property names carrying the OS family name.
var osNameKeys = []string{
	"syft:image:os:name",
	"syft:distro:id",
	"aquasecurity:trivy:OS:Family",
}

// osVersionKeys are property names carrying the OS version identifier.
var osVersionKeys = []string{
	"syft:image:os:version-id",
	"syft:distro:version-id",
}

func flavorFromOSMetadata(bom *cdx.BOM) string {
	if bom == nil || bom.Metadata == nil {
		return ""
	}
	var propSets [][]cdx.Property
	if bom.Metadata.Component != nil {
		propSets = append(propSets, propertySlice(bom.Metadata.Component.Properties))
	}
	propSets = append(propSets, propertySlice(bom.Metadata.Properties))

	osName := findPropValue(propSets, osNameKeys)
	if osName == "" {
		return ""
	}
	osName = strings.ToLower(osName)
	if ver := strings.ToLower(findPropValue(propSets, osVersionKeys)); ver != "" {
		return osName + "-" + ver
	}
	return osName
}

// findPropValue searches property sets in order, returning the first value
// found for any of the given keys.
func findPropValue(propSets [][]cdx.Property, keys []string) string {
	for _, props := range propSets {
		for _, p := range props {
			for _, k := range keys {
				if p.Name == k && p.Value != "" {
					return p.Value
				}
			}
		}
	}
	return ""
}

// --- Layer 2: purl-type fingerprint ---

// osPMTypes are the package-manager purl types considered "OS-level".
var osPMTypes = []string{"apk", "deb", "rpm"}

func flavorFromPURLs(bom *cdx.BOM) string {
	if bom == nil || bom.Components == nil {
		return ""
	}
	comps := *bom.Components
	if len(comps) == 0 {
		return "scratch"
	}

	typeCounts, apkDistros := countPURLTypes(comps)
	if len(typeCounts) == 0 {
		return "distroless"
	}

	osPMTotal := 0
	for _, t := range osPMTypes {
		osPMTotal += typeCounts[t]
	}
	if osPMTotal == 0 {
		return "distroless"
	}

	dominant := dominantOSPMType(typeCounts, osPMTotal)
	return flavorForDominant(dominant, comps, apkDistros)
}

// countPURLTypes tallies purl types across components and tracks apk distro qualifiers.
func countPURLTypes(comps []cdx.Component) (map[string]int, map[string]int) {
	typeCounts := map[string]int{}
	apkDistros := map[string]int{} // "wolfi", "chainguard", "alpine"

	for i := range comps {
		purl := comps[i].PackageURL
		if purl == "" {
			continue
		}
		typ := purlType(purl)
		if typ == "" {
			continue
		}
		typeCounts[typ]++
		if typ == "apk" {
			distro := strings.ToLower(purlDistroQualifier(purl))
			apkDistros[apkDistroKey(distro)]++
		}
	}
	return typeCounts, apkDistros
}

// apkDistroKey maps a raw distro qualifier value to the canonical flavor key.
func apkDistroKey(distro string) string {
	switch {
	case strings.HasPrefix(distro, "wolfi"):
		return "wolfi"
	case strings.HasPrefix(distro, "chainguard"):
		return "chainguard"
	default:
		return "alpine"
	}
}

// dominantOSPMType returns the OS-pm type that has a strict majority (>50%),
// or "" if there is a tie.
func dominantOSPMType(typeCounts map[string]int, osPMTotal int) string {
	for _, t := range osPMTypes {
		if typeCounts[t]*2 > osPMTotal {
			return t
		}
	}
	return ""
}

// flavorForDominant maps a dominant purl type to a flavor string.
func flavorForDominant(dominant string, comps []cdx.Component, apkDistros map[string]int) string {
	switch dominant {
	case "apk":
		return apkFlavor(apkDistros)
	case "deb":
		return debFlavor(comps)
	case "rpm":
		return rpmFlavor(comps)
	default:
		return "" // tie — fall through to layer 3
	}
}

// apkFlavor returns the flavor for an APK-dominant SBOM using distro qualifier votes.
func apkFlavor(apkDistros map[string]int) string {
	total := apkDistros["wolfi"] + apkDistros["chainguard"] + apkDistros["alpine"]
	for _, key := range []string{"wolfi", "chainguard", "alpine"} {
		if apkDistros[key]*2 > total {
			return key
		}
	}
	return "" // tie — fall through to layer 3
}

func debFlavor(comps []cdx.Component) string {
	for i := range comps {
		if purlType(comps[i].PackageURL) != "deb" {
			continue
		}
		if strings.Contains(purlNamespace(comps[i].PackageURL), "ubuntu") {
			return "ubuntu"
		}
	}
	return "debian"
}

func rpmFlavor(comps []cdx.Component) string {
	for i := range comps {
		if purlType(comps[i].PackageURL) != "rpm" {
			continue
		}
		ns := purlNamespace(comps[i].PackageURL)
		switch {
		case strings.Contains(ns, "fedora"):
			return "fedora"
		case strings.Contains(ns, "rhel") || strings.Contains(ns, "redhat") || strings.Contains(ns, "centos"):
			return "rhel"
		}
	}
	return "rpm-other"
}

// --- Layer 3: tag suffix heuristic ---

// tagSuffixes is sorted longest-first so that the longest match wins.
var tagSuffixes = []string{
	"-debian-slim", "-bookworm-slim", "-bullseye-slim", "-ubi-minimal", "-ubi-micro",
	"-alpine3", "-alpine", "-wolfi", "-chainguard",
	"-bookworm", "-bullseye", "-debian",
	"-ubuntu", "-jammy", "-noble", "-focal",
	"-distroless", "-scratch", "-slim",
	"-rhel", "-ubi", "-fedora",
}

func flavorFromTagSuffix(subjectVersion string) string {
	lower := strings.ToLower(subjectVersion)
	for _, suffix := range tagSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return suffix[1:] // strip leading '-'
		}
	}
	return ""
}

// --- PURL parsing helpers ---

// purlType returns the type segment of a purl (e.g., "apk" from "pkg:apk/...").
func purlType(purl string) string {
	s, _, ok := strings.Cut(purl, "/")
	if !ok {
		return ""
	}
	_, t, ok := strings.Cut(s, ":")
	if !ok {
		return ""
	}
	return strings.ToLower(t)
}

// purlNamespace returns the namespace segment of a purl (e.g., "ubuntu" from "pkg:deb/ubuntu/curl@...").
func purlNamespace(purl string) string {
	base, _, _ := strings.Cut(purl, "?")
	base, _, _ = strings.Cut(base, "#")
	parts := strings.SplitN(base, "/", 3)
	if len(parts) < 3 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// purlDistroQualifier returns the value of the "distro" qualifier from a purl.
func purlDistroQualifier(purl string) string {
	_, qs, ok := strings.Cut(purl, "?")
	if !ok {
		return ""
	}
	qs, _, _ = strings.Cut(qs, "#")
	for _, kv := range strings.Split(qs, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.EqualFold(k, "distro") {
			return v
		}
	}
	return ""
}
