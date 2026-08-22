package enrichment

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
	"github.com/pfenerty/ocidex/internal/repository"
)

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
//
// A transition *to* "unsigned" is held back one recheck cycle before it
// becomes an event. Every other verdict rests on positive evidence —
// artifact_missing on a 404 HEAD, trust_config_changed on a matching signer —
// but "unsigned" is the absence of evidence, so any silent discovery failure
// is indistinguishable from a removed signature. Requiring two consecutive
// observations to agree means one bad lookup can no longer raise a false
// alarm. The pending row lives in provenance_drift_pending; see that
// migration for the full rationale.
//
// Malformed provenance JSON is log-and-degrade, not a hard error: it's
// enricher output, not user input, so a bad row just means no drift event is
// recorded for this enrichment cycle. See also GetSBOM in
// internal/service/search_sbom.go, which applies the same policy. Pending-store
// failures degrade the same way — they cost a confirmation cycle, never an
// enrichment.
func (d *Dispatcher) recordProvenanceDrift(ctx context.Context, sbomID pgtype.UUID, oldData, newData []byte) {
	var oldP, newP provenance.Provenance
	if err := json.Unmarshal(oldData, &oldP); err != nil {
		d.logger.Error("parsing previous provenance enrichment", "sbom_id", sbomID, "err", err)
		return
	}
	if err := json.Unmarshal(newData, &newP); err != nil {
		d.logger.Error("parsing new provenance enrichment", "sbom_id", sbomID, "err", err)
		return
	}

	oldStatus := provenance.SigningStatus(oldP)
	newStatus := provenance.SigningStatus(newP)

	// Resolve any held-back observation first. It has to come before the
	// newStatus == oldStatus check below: once an unsigned result is stored,
	// both sides of that comparison read "unsigned", so a confirmation would
	// never be reached.
	if pending, ok := d.pendingDrift(ctx, sbomID); ok {
		d.clearPendingDrift(ctx, sbomID)
		if newStatus == pending.NewStatus {
			d.insertDrift(ctx, repository.InsertProvenanceDriftParams{
				SbomID:         sbomID,
				PreviousStatus: pending.PreviousStatus,
				NewStatus:      newStatus,
				Reason:         pending.Reason,
				PreviousData:   pending.PreviousData,
				NewData:        newData,
			})
			return
		}
		// The two observations disagree, so the first was transient. Fall
		// through and judge this cycle on its own merits.
	}

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

	if newStatus == "unsigned" {
		if err := d.store.UpsertProvenanceDriftPending(ctx, repository.UpsertProvenanceDriftPendingParams{
			SbomID:         sbomID,
			PreviousStatus: oldStatus,
			NewStatus:      newStatus,
			Reason:         reason,
			PreviousData:   oldData,
			NewData:        newData,
		}); err != nil {
			d.logger.Error("failed to record pending provenance drift", "sbom_id", sbomID, "err", err)
		}
		return
	}

	d.insertDrift(ctx, repository.InsertProvenanceDriftParams{
		SbomID:         sbomID,
		PreviousStatus: oldStatus,
		NewStatus:      newStatus,
		Reason:         reason,
		PreviousData:   oldData,
		NewData:        newData,
	})
}

// pendingDrift returns the held-back observation for sbomID, if any. A missing
// row is the common case, not an error.
func (d *Dispatcher) pendingDrift(ctx context.Context, sbomID pgtype.UUID) (repository.ProvenanceDriftPending, bool) {
	pending, err := d.store.GetProvenanceDriftPending(ctx, sbomID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			d.logger.Error("reading pending provenance drift", "sbom_id", sbomID, "err", err)
		}
		return repository.ProvenanceDriftPending{}, false
	}
	return pending, true
}

func (d *Dispatcher) clearPendingDrift(ctx context.Context, sbomID pgtype.UUID) {
	if err := d.store.DeleteProvenanceDriftPending(ctx, sbomID); err != nil {
		d.logger.Error("clearing pending provenance drift", "sbom_id", sbomID, "err", err)
	}
}

func (d *Dispatcher) insertDrift(ctx context.Context, params repository.InsertProvenanceDriftParams) {
	if err := d.store.InsertProvenanceDrift(ctx, params); err != nil {
		d.logger.Error("failed to record provenance drift", "sbom_id", params.SbomID, "err", err)
	}
}
