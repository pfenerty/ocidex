package enrichment

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
	"github.com/pfenerty/ocidex/internal/repository"
)

// signingStatus derives the same terminal status the signing_status SQL CASE
// expression computes, from a single provenance enrichment's data.
func signingStatus(p provenance.Provenance) string {
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

// sameSigner reports whether a and b carry the same non-empty signer
// identity (public-key fingerprint, or keyless identity+issuer). Used to
// tell "our trust config changed" (same signer, different verification
// outcome) apart from "the signature itself is gone" (no comparable signer
// at all).
func sameSigner(a, b provenance.Provenance) bool {
	if a.SignerFingerprint != "" && a.SignerFingerprint == b.SignerFingerprint {
		return true
	}
	if a.SignerIdentity != "" && a.SignerIssuer != "" &&
		a.SignerIdentity == b.SignerIdentity && a.SignerIssuer == b.SignerIssuer {
		return true
	}
	return false
}

// recordProvenanceDrift compares a SBOM's previous successful provenance
// enrichment against its just-stored new one and, if the signing status
// meaningfully changed, inserts a provenance_drift_events row.
func (d *Dispatcher) recordProvenanceDrift(ctx context.Context, sbomID pgtype.UUID, oldData, newData []byte) {
	var oldP, newP provenance.Provenance
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
	case sameSigner(oldP, newP):
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
