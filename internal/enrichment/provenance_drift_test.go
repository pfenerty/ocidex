package enrichment

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
)

// ---------------------------------------------------------------------------
// sameSigner
// ---------------------------------------------------------------------------

func TestSameSigner_MatchingFingerprint(t *testing.T) {
	a := provenance.Provenance{SignerFingerprint: "abc123"}
	b := provenance.Provenance{SignerFingerprint: "abc123"}
	if !sameSigner(a, b) {
		t.Error("expected same signer for matching fingerprint")
	}
}

func TestSameSigner_MatchingIdentityAndIssuer(t *testing.T) {
	a := provenance.Provenance{SignerIdentity: "user@example.com", SignerIssuer: "https://issuer.example.com"}
	b := provenance.Provenance{SignerIdentity: "user@example.com", SignerIssuer: "https://issuer.example.com"}
	if !sameSigner(a, b) {
		t.Error("expected same signer for matching identity+issuer")
	}
}

func TestSameSigner_DifferentFingerprint(t *testing.T) {
	a := provenance.Provenance{SignerFingerprint: "abc123"}
	b := provenance.Provenance{SignerFingerprint: "def456"}
	if sameSigner(a, b) {
		t.Error("expected different signers for mismatched fingerprint")
	}
}

func TestSameSigner_DifferentIdentityOrIssuer(t *testing.T) {
	a := provenance.Provenance{SignerIdentity: "user@example.com", SignerIssuer: "https://issuer-a.example.com"}
	b := provenance.Provenance{SignerIdentity: "user@example.com", SignerIssuer: "https://issuer-b.example.com"}
	if sameSigner(a, b) {
		t.Error("expected different signers when issuer differs despite matching identity")
	}
}

func TestSameSigner_EmptyFieldsDoNotMatch(t *testing.T) {
	a := provenance.Provenance{}
	b := provenance.Provenance{}
	if sameSigner(a, b) {
		t.Error("expected no match when both sides have no signer info at all")
	}
}

// ---------------------------------------------------------------------------
// recordProvenanceDrift
// ---------------------------------------------------------------------------

func TestRecordProvenanceDrift_RegressionOnlyGuard(t *testing.T) {
	// Old status "unsigned" is not in the {verified, signed} set the guard
	// requires, so even though the new status differs, no drift should record.
	oldData := provenanceJSON(t, map[string]any{})
	newData := provenanceJSON(t, map[string]any{"verified": false})

	store := &fakeStore{}
	d := NewDispatcher(store, NewCatalog())

	sbomID := pgtype.UUID{Bytes: [16]byte{20}, Valid: true}
	d.recordProvenanceDrift(t.Context(), sbomID, oldData, newData)

	if drifts := store.driftResults(); len(drifts) != 0 {
		t.Errorf("expected no drift event when old status is not verified/signed, got %d", len(drifts))
	}
}

func TestRecordProvenanceDrift_SilentlyReturnsOnMalformedOldData(t *testing.T) {
	oldData := []byte("not json")
	newData := provenanceJSON(t, map[string]any{"verified": false})

	store := &fakeStore{}
	d := NewDispatcher(store, NewCatalog())

	sbomID := pgtype.UUID{Bytes: [16]byte{21}, Valid: true}
	d.recordProvenanceDrift(t.Context(), sbomID, oldData, newData)

	if drifts := store.driftResults(); len(drifts) != 0 {
		t.Errorf("expected no drift event on malformed old data, got %d", len(drifts))
	}
}

func TestRecordProvenanceDrift_SilentlyReturnsOnMalformedNewData(t *testing.T) {
	oldData := provenanceJSON(t, map[string]any{"verified": true, "signerFingerprint": "abc123"})
	newData := []byte("{ also not valid")

	store := &fakeStore{}
	d := NewDispatcher(store, NewCatalog())

	sbomID := pgtype.UUID{Bytes: [16]byte{22}, Valid: true}
	d.recordProvenanceDrift(t.Context(), sbomID, oldData, newData)

	if drifts := store.driftResults(); len(drifts) != 0 {
		t.Errorf("expected no drift event on malformed new data, got %d", len(drifts))
	}
}
