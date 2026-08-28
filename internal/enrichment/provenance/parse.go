package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	slsav1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intotov1 "github.com/in-toto/attestation/go/v1"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"google.golang.org/protobuf/encoding/protojson"
)

// Provenance is the parsed result stored in the enrichment JSONB column
// for enricher_name="provenance". Verified remains nil until B4 wires ECDSA verification.
type Provenance struct {
	SignaturePresent   bool       `json:"signaturePresent"`
	AttestationPresent bool       `json:"attestationPresent"`
	SignerFingerprint  string     `json:"signerFingerprint,omitempty"` // DSSE signatures[0].keyid
	PredicateType      string     `json:"predicateType,omitempty"`
	BuilderID          string     `json:"builderId,omitempty"`
	SourceURI          string     `json:"sourceUri,omitempty"`
	SourceCommit       string     `json:"sourceCommit,omitempty"`
	BuildStartedOn     *time.Time `json:"buildStartedOn,omitempty"`
	Subjects           []string   `json:"subjects,omitempty"` // "name@sha256:digest"
	RekorUUID          string     `json:"rekorUuid,omitempty"`
	RekorLogIndex      int64      `json:"rekorLogIndex,omitempty"`
	Verified           *bool      `json:"verified,omitempty"`        // nil until B4
	SignerIdentity     string     `json:"signerIdentity,omitempty"`  // keyless only: matched trust_identity pattern
	SignerIssuer       string     `json:"signerIssuer,omitempty"`    // keyless only: matched trust_issuer
	ArtifactMissing    bool       `json:"artifactMissing,omitempty"` // true when the registry no longer has this digest
}

// --- internal parsing types --------------------------------------------------

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"` // base64-encoded in-toto statement
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// sigstoreBundle is the JSON shape of a Sigstore Bundle
// (application/vnd.dev.sigstore.bundle.v0.3+json). It wraps the same DSSE
// envelope one level deeper than the raw-DSSE attArtifactType case, and it
// carries the certificate and Rekor entry inline rather than in layer
// annotations — which is why a bundle needs its own Rekor extraction and its
// own verification path.
//
// logIndex is a string because the bundle is protobuf-defined and protojson
// encodes int64 as a JSON string.
type sigstoreBundle struct {
	DSSEEnvelope         dsseEnvelope `json:"dsseEnvelope"`
	VerificationMaterial struct {
		TlogEntries []struct {
			LogIndex string `json:"logIndex"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
}

// inTotoPredicate is the minimum of an in-toto statement needed to tell a
// bundle signature from a bundle attestation. Decoded with encoding/json
// rather than parseInTotoStatement's protojson so that classification cannot
// fail on a predicate shape we do not model.
type inTotoPredicate struct {
	PredicateType string `json:"predicateType"`
}

// --- entry point -------------------------------------------------------------

// buildProvenance converts raw discovered bytes into a parsed Provenance.
//
// Where several signatures or attestations are attached, the first is the
// reported one. That is a pre-verification default, so an image that never gets
// verified still describes itself: once verification runs, applyTrust re-stamps
// the Rekor fields from the signature that actually matched (ocidex-r27f).
func buildProvenance(raw RawArtifacts) Provenance {
	p := Provenance{
		SignaturePresent:   raw.SigPresent(),
		AttestationPresent: raw.AttPresent(),
		ArtifactMissing:    raw.ArtifactMissing,
	}
	if raw.SigPresent() {
		extractFromSigLayer(&p, raw.Sigs[0])
	}
	if raw.AttPresent() {
		att := raw.Atts[0]
		switch att.ArtifactType {
		case inTotoArtifactType:
			extractFromRawInToto(&p, att.Bytes)
		case bundleArtifactType:
			extractFromSigstoreBundle(&p, att.Bytes)
		default:
			extractFromAtt(&p, att.Bytes)
		}
	}
	return p
}

// --- sig extraction ----------------------------------------------------------

// extractFromSigLayer reads Rekor transparency data from one signature layer,
// whichever of the two formats it is in. A new-format Sigstore bundle carries
// no layer annotations at all — its tlog entry is inside the blob — so the
// annotation path would silently find nothing and the UI would lose its Rekor
// link.
func extractFromSigLayer(p *Provenance, l signedLayer) {
	if l.ArtifactType == bundleArtifactType {
		extractRekorFromBundle(p, l.Bytes)
		return
	}
	extractFromSig(p, l.Annotations)
}

// extractRekorFromBundle reads the log index from a bundle signature's inline
// transparency-log entry.
//
// It deliberately does not touch PredicateType or Subjects: the enclosing
// in-toto statement is cosign's signature marker (no predicate, an unnamed
// subject), so surfacing either would put noise where an attestation's real
// values belong.
func extractRekorFromBundle(p *Provenance, layerBytes []byte) {
	var b sigstoreBundle
	if err := json.Unmarshal(layerBytes, &b); err != nil {
		return
	}
	for _, e := range b.VerificationMaterial.TlogEntries {
		if n, err := strconv.ParseInt(e.LogIndex, 10, 64); err == nil && n > 0 {
			p.RekorLogIndex = n
			return
		}
	}
}

// bundleIsSignature reports whether a Sigstore bundle carries a signature
// rather than an attestation, by reading the in-toto predicateType out of its
// DSSE payload.
//
// The manifest's dev.sigstore.bundle.predicateType annotation is not usable
// for this: cilium's 5 MB SPDX attestation bundle sets it to the signature
// value too, so it would classify both referrers the same way. The payload is
// the only trustworthy discriminator, and it is what cosign's own CLI reports.
func bundleIsSignature(layerBytes []byte) bool {
	var b sigstoreBundle
	if err := json.Unmarshal(layerBytes, &b); err != nil {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return false
	}
	var stmt inTotoPredicate
	if err := json.Unmarshal(decoded, &stmt); err != nil {
		return false
	}
	return stmt.PredicateType == cosignSignPredicateType
}

// extractFromSig reads Rekor transparency data from manifest annotations.
// The simplesigning layer bytes have no fingerprint field — the signer is in the DSSE envelope.
func extractFromSig(p *Provenance, annotations map[string]string) {
	// Rekor transparency URL: e.g. https://rekor.sigstore.dev/...?logIndex=N
	if transparency := annotations["chains.tekton.dev/transparency"]; transparency != "" {
		if u, err := url.Parse(transparency); err == nil {
			if idx := u.Query().Get("logIndex"); idx != "" {
				if n, err := strconv.ParseInt(idx, 10, 64); err == nil {
					p.RekorLogIndex = n
				}
			}
		}
	}

	// Cosign bundle annotation: JSON with Payload.logIndex.
	if bundleJSON := annotations["dev.sigstore.cosign/bundle"]; bundleJSON != "" {
		var b cbundle.RekorBundle
		if err := json.Unmarshal([]byte(bundleJSON), &b); err == nil && b.Payload.LogIndex > 0 {
			p.RekorLogIndex = b.Payload.LogIndex
		}
	}
}

// restampFromSig re-derives the Rekor fields from the signature that actually
// verified. buildProvenance seeded them from Sigs[0], which on a multiply signed
// image is usually the wrong one — registry.k8s.io lists its krel-staging
// signature first and its krel-trust signature second. The existing value is
// cleared first so a winning signature carrying no Rekor bundle does not inherit
// the losing signature's log index.
func restampFromSig(p *Provenance, l signedLayer) {
	p.RekorLogIndex = 0
	extractFromSigLayer(p, l)
}

const rekorBaseURL = "https://rekor.sigstore.dev"

// fetchRekorUUIDFn is the seam tests substitute to observe the deadline Enrich
// hands the Rekor lookup, mirroring fetchTrustedRootFn in keyless.go.
var fetchRekorUUIDFn = fetchRekorUUID

// fetchRekorUUID fetches the Rekor transparency log UUID for the given log index.
// Returns "" on any error — Rekor is external and non-critical (fail-open).
func fetchRekorUUID(ctx context.Context, logIndex int64) string {
	return fetchRekorUUIDFromBase(ctx, rekorBaseURL, logIndex)
}

// fetchRekorUUIDFromBase is the testable core: it accepts a base URL so tests
// can substitute an httptest.Server without hitting the public Rekor instance.
// It uses the upstream sigstore/rekor generated client rather than a
// hand-rolled HTTP request — it already carries retry and response-decoding
// logic we'd otherwise have to duplicate, and cosign pulls in go-openapi for
// this exact purpose.
func fetchRekorUUIDFromBase(ctx context.Context, baseURL string, logIndex int64) string {
	c, err := rekorclient.GetRekorClient(baseURL)
	if err != nil {
		return ""
	}
	params := entries.NewGetLogEntryByIndexParamsWithContext(ctx).WithLogIndex(logIndex)
	resp, err := c.Entries.GetLogEntryByIndex(params)
	if err != nil {
		return ""
	}
	for uuid := range resp.Payload {
		return uuid
	}
	return ""
}

// --- att extraction ----------------------------------------------------------

// extractFromRawInToto parses a buildkit-native in-toto statement (not DSSE-wrapped).
// The layer bytes are raw JSON — no envelope, no base64 encoding.
func extractFromRawInToto(p *Provenance, layerBytes []byte) {
	stmt, err := parseInTotoStatement(layerBytes)
	if err != nil {
		return
	}
	applyInTotoStatement(p, stmt)
}

// extractFromAtt parses the DSSE envelope and the SLSA in-toto statement inside it.
func extractFromAtt(p *Provenance, layerBytes []byte) {
	var env dsseEnvelope
	if err := json.Unmarshal(layerBytes, &env); err != nil {
		return
	}
	extractFromDSSE(p, env)
}

// extractFromSigstoreBundle parses a Sigstore Bundle
// (application/vnd.dev.sigstore.bundle.v0.3+json). Cosign has moved toward
// this format for newer attestations; it wraps the same DSSE envelope one
// level deeper than the raw-DSSE case handled by extractFromAtt.
func extractFromSigstoreBundle(p *Provenance, layerBytes []byte) {
	var bundle sigstoreBundle
	if err := json.Unmarshal(layerBytes, &bundle); err != nil {
		return
	}
	extractFromDSSE(p, bundle.DSSEEnvelope)
}

// extractFromDSSE parses the SLSA in-toto statement inside an already-decoded
// DSSE envelope. Shared by extractFromAtt and extractFromSigstoreBundle, which
// differ only in how they arrive at the envelope.
func extractFromDSSE(p *Provenance, env dsseEnvelope) {
	if len(env.Signatures) > 0 {
		p.SignerFingerprint = env.Signatures[0].KeyID
	}

	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return
	}

	stmt, err := parseInTotoStatement(decoded)
	if err != nil {
		return
	}
	applyInTotoStatement(p, stmt)
}

// parseInTotoStatement decodes raw in-toto statement JSON into the upstream
// protobuf-generated Statement type. in-toto/attestation types are
// protobuf-generated (structpb.Struct/timestamppb.Timestamp under the hood,
// with "json" struct tags that are cosmetic protoc-gen-go remnants rather
// than the real wire field names — e.g. Statement.Type actually serializes
// as "_type" per the in-toto spec), so they must be decoded with protojson
// rather than encoding/json.
func parseInTotoStatement(data []byte) (*intotov1.Statement, error) {
	stmt := &intotov1.Statement{}
	if err := protojson.Unmarshal(data, stmt); err != nil {
		return nil, err
	}
	return stmt, nil
}

// applyInTotoStatement copies fields from a decoded in-toto Statement into p.
// The predicate is a generic structpb.Struct at the Statement level (any
// in-toto predicate type is legal there); it's round-tripped through
// protojson into the typed SLSA v1 Provenance predicate here. A non-SLSA or
// malformed predicate simply leaves the SLSA-specific fields unset.
func applyInTotoStatement(p *Provenance, stmt *intotov1.Statement) {
	p.PredicateType = stmt.GetPredicateType()
	for _, s := range stmt.GetSubject() {
		if sha, ok := s.GetDigest()["sha256"]; ok {
			p.Subjects = append(p.Subjects, s.GetName()+"@sha256:"+sha)
		}
	}

	if stmt.GetPredicate() == nil {
		return
	}
	predJSON, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		return
	}
	var pred slsav1.Provenance
	if err := protojson.Unmarshal(predJSON, &pred); err != nil {
		return
	}

	p.BuilderID = pred.GetRunDetails().GetBuilder().GetId()
	if ts := pred.GetRunDetails().GetMetadata().GetStartedOn(); ts != nil {
		t := ts.AsTime()
		p.BuildStartedOn = &t
	}

	// Source: prefer git+ dependency (standard SLSA); oci:// and other schemes are skipped.
	for _, dep := range pred.GetBuildDefinition().GetResolvedDependencies() {
		if strings.HasPrefix(dep.GetUri(), "git+") {
			p.SourceURI = strings.TrimPrefix(dep.GetUri(), "git+")
			if commit, ok := dep.GetDigest()["sha1"]; ok {
				p.SourceCommit = commit
			}
			break
		}
	}
}
