// Reading the subject's identity out of a CycloneDX BOM — version,
// architecture, build date, digest — and the nullable-column helpers that
// carry the result into the database. Split out of sbom.go.

package service

import (
	"context"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
)

// ociVersionKeys are property names that contain a human-readable image version.
var ociVersionKeys = []string{
	"syft:image:labels:org.opencontainers.image.version",
	"aquasecurity:trivy:Labels:org.opencontainers.image.version",
	"syft:image:labels:org.label-schema.version", // legacy
}

// ociArchKeys are property names that contain the image architecture.
var ociArchKeys = []string{
	"syft:image:labels:org.opencontainers.image.architecture",
}

// ociBuildDateKeys are property names that contain the image build date.
var ociBuildDateKeys = []string{
	"syft:image:labels:org.opencontainers.image.created",
	"syft:image:labels:org.label-schema.build-date", // legacy
}

// isMoreSpecific reports whether candidate is a patch-level refinement of base:
// same major.minor, base has no patch component, candidate has a valid patch.
func isMoreSpecific(candidate, base string) bool {
	cMaj, cMin, cPatch := parseSemver(candidate)
	bMaj, bMin, bPatch := parseSemver(base)
	return cMaj >= 0 && cMin >= 0 && cPatch >= 0 &&
		bMaj == cMaj && bMin == cMin &&
		bPatch < 0
}

// resolveSubjectVersion returns the human-readable version for an SBOM's subject.
// params.Version takes precedence; then metadata.component.version when it is not
// a digest; then well-known OCI label properties emitted by Syft and Trivy.
func resolveSubjectVersion(bom *cdx.BOM, params IngestParams) pgtype.Text {
	// Identity may be declared entirely by the caller, with no subject
	// component in the BOM to fall back to (ADR-040).
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return pgtype.Text{String: params.Version, Valid: params.Version != ""}
	}

	if params.Version != "" {
		mc := bom.Metadata.Component
		if mc != nil && mc.Version != "" && !strings.HasPrefix(mc.Version, "sha256:") {
			if isMoreSpecific(mc.Version, params.Version) {
				return pgtype.Text{String: mc.Version, Valid: true}
			}
		}
		return pgtype.Text{String: params.Version, Valid: true}
	}

	mc := bom.Metadata.Component

	// Use the explicit version if it exists and isn't a digest.
	if mc.Version != "" && !strings.HasPrefix(mc.Version, "sha256:") {
		return pgtype.Text{String: mc.Version, Valid: true}
	}

	// Search component properties, then top-level metadata properties.
	for _, props := range [][]cdx.Property{propertySlice(mc.Properties), propertySlice(bom.Metadata.Properties)} {
		for _, p := range props {
			for _, key := range ociVersionKeys {
				if p.Name == key && p.Value != "" {
					return pgtype.Text{String: p.Value, Valid: true}
				}
			}
		}
	}

	return pgtype.Text{}
}

// resolveArchitecture returns the image architecture from params or BOM properties.
func resolveArchitecture(bom *cdx.BOM, params IngestParams) string {
	if params.Architecture != "" {
		return params.Architecture
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}
	mc := bom.Metadata.Component
	for _, props := range [][]cdx.Property{propertySlice(mc.Properties), propertySlice(bom.Metadata.Properties)} {
		for _, p := range props {
			for _, key := range ociArchKeys {
				if p.Name == key && p.Value != "" {
					return p.Value
				}
			}
		}
	}
	return ""
}

// resolveBuildDate returns the image build date from params or BOM properties.
func resolveBuildDate(bom *cdx.BOM, params IngestParams) string {
	if params.BuildDate != "" {
		return params.BuildDate
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}
	mc := bom.Metadata.Component
	for _, props := range [][]cdx.Property{propertySlice(mc.Properties), propertySlice(bom.Metadata.Properties)} {
		for _, p := range props {
			for _, key := range ociBuildDateKeys {
				if p.Name == key && p.Value != "" {
					return p.Value
				}
			}
		}
	}
	return ""
}

// propertySlice safely dereferences a *[]cdx.Property.
func propertySlice(p *[]cdx.Property) []cdx.Property {
	if p == nil {
		return nil
	}
	return *p
}

// parseSemver extracts major, minor, patch from a version string.
// Returns -1 for any part that cannot be parsed.
func parseSemver(version string) (major, minor, patch int) {
	major, minor, patch = -1, -1, -1
	if version == "" {
		return
	}
	// Strip leading 'v' if present.
	version = strings.TrimPrefix(version, "v")
	parts := strings.SplitN(version, ".", 3)

	if len(parts) >= 1 {
		if v, err := strconv.Atoi(parts[0]); err == nil {
			major = v
		}
	}
	if len(parts) >= 2 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			minor = v
		}
	}
	if len(parts) >= 3 {
		// Strip pre-release suffix (e.g., "1-beta" → "1").
		patchStr := strings.SplitN(parts[2], "-", 2)[0]
		patchStr = strings.SplitN(patchStr, "+", 2)[0]
		if v, err := strconv.Atoi(patchStr); err == nil {
			patch = v
		}
	}
	return
}

// textOrNull returns a valid pgtype.Text if s is non-empty, null otherwise.
func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// boolOrNull returns a valid pgtype.Bool when b is true, null otherwise.
// This allows the SQL query to skip the filter when the value is not set.
func boolOrNull(b bool) pgtype.Bool {
	if !b {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: true, Valid: true}
}

// intOrNull returns a valid pgtype.Int4 if v >= 0, null otherwise.
func intOrNull(v int) pgtype.Int4 {
	if v < 0 {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(v), Valid: true} //nolint:gosec // semver parts are always small
}

// extractDigestFromBOM returns the image digest from a BOM's metadata component,
// mirroring the extraction logic in resolveArtifact.
// resolveIngestDigest returns the digest that identifies this ingest's subject,
// preferring the caller's declaration over the BOM (ADR-040).
func resolveIngestDigest(bom *cdx.BOM, params IngestParams) string {
	if params.Digest != "" {
		return params.Digest
	}
	return extractDigestFromBOM(bom)
}

func extractDigestFromBOM(bom *cdx.BOM) string {
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}
	mc := bom.Metadata.Component
	if idx := strings.Index(mc.Name, "@sha256:"); idx != -1 {
		return mc.Name[idx+1:]
	}
	if strings.HasPrefix(mc.Version, "sha256:") {
		return mc.Version
	}
	return ""
}

// validateContainerDigest checks that container SBOMs reference a single image
// manifest, not a manifest list. Skipped if no validator is configured.
func (s *sbomService) validateContainerDigest(ctx context.Context, bom *cdx.BOM) error {
	if s.digestValidator == nil {
		return nil
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil
	}
	mc := bom.Metadata.Component
	if mc.Type != cdx.ComponentTypeContainer {
		return nil
	}

	// Extract name and digest the same way resolveArtifact does.
	name := mc.Name
	var digest string
	if idx := strings.Index(name, "@sha256:"); idx != -1 {
		digest = name[idx+1:]
		name = name[:idx]
	}
	if digest == "" && strings.HasPrefix(mc.Version, "sha256:") {
		digest = mc.Version
	}
	if digest == "" {
		return nil
	}

	if err := s.digestValidator.ValidateDigest(ctx, name, digest); err != nil {
		return &ValidationError{Message: err.Error()}
	}
	return nil
}
