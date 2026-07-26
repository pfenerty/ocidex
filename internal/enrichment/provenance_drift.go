package enrichment

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// provenanceFields mirrors the subset of provenance.Provenance's JSON shape
// needed to classify drift. It's a local, minimal copy rather than an import
// of internal/enrichment/provenance: that package already imports this one
// (for enrichment.SubjectRef), so importing it back would cycle. Keep the
// json tags in sync with provenance.Provenance and the signing_status CASE
// expression in db/queries/artifact.sql.
type provenanceFields struct {
	ArtifactMissing    bool   `json:"artifactMissing"`
	Verified           *bool  `json:"verified"`
	SignaturePresent   bool   `json:"signaturePresent"`
	AttestationPresent bool   `json:"attestationPresent"`
	SignerFingerprint  string `json:"signerFingerprint"`
	SignerIdentity     string `json:"signerIdentity"`
	SignerIssuer       string `json:"signerIssuer"`
}

// signingStatus derives the same terminal status the signing_status SQL CASE
// expression computes, from a single provenance enrichment's JSON data.
func signingStatus(p provenanceFields) string {
	switch {
	case p.ArtifactMissing:
		return "artifact_missing"
	case p.Verified != nil && *p.Verified:
		return "verified"
	case p.Verified != nil && !*p.Verified:
		return "verification_failed"
	case p.SignaturePresent || p.AttestationPresent:
		return "signed"
	default:
		return "unsigned"
	}
}

// hasSameSigner reports whether old and new carry the same non-empty signer
// identity (public-key fingerprint, or keyless identity+issuer). Used to tell
// "our trust config changed" (same signer, different verification outcome)
// apart from "the signature itself is gone" (no comparable signer at all).
func (p provenanceFields) hasSameSigner(other provenanceFields) bool {
	if p.SignerFingerprint != "" && p.SignerFingerprint == other.SignerFingerprint {
		return true
	}
	if p.SignerIdentity != "" && p.SignerIssuer != "" &&
		p.SignerIdentity == other.SignerIdentity && p.SignerIssuer == other.SignerIssuer {
		return true
	}
	return false
}

// recordProvenanceDrift compares a SBOM's previous successful provenance
// enrichment against its just-stored new one and, if the signing status
// meaningfully changed, inserts a provenance_drift_events row.
func (d *Dispatcher) recordProvenanceDrift(ctx context.Context, sbomID pgtype.UUID, oldData, newData []byte) {
	var oldP, newP provenanceFields
	if err := json.Unmarshal(oldData, &oldP); err != nil {
		return
	}
	if err := json.Unmarshal(newData, &newP); err != nil {
		return
	}

	oldStatus := signingStatus(oldP)
	newStatus := signingStatus(newP)
	if newStatus == oldStatus {
		return
	}
	if oldStatus != "verified" && oldStatus != "signed" {
		return
	}

	reason := "reverification_failed"
	switch {
	case newP.ArtifactMissing:
		reason = "artifact_missing"
	case oldP.hasSameSigner(newP):
		reason = "trust_config_changed"
	}

	if err := d.store.InsertProvenanceDrift(ctx, repository.InsertProvenanceDriftParams{
		SbomID:         sbomID,
		PreviousStatus: oldStatus,
		NewStatus:      newStatus,
		Reason:         reason,
		PreviousData:   oldData,
		NewData:        newData,
	}); err != nil {
		d.logger.Error("failed to record provenance drift", "sbom_id", sbomID, "err", err)
	}
}
