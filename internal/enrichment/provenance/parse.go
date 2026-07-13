package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	Verified           *bool      `json:"verified,omitempty"` // nil until B4
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

// sigstoreBundle is the JSON shape of a Sigstore Bundle attestation
// (application/vnd.dev.sigstore.bundle.v0.3+json). It wraps the same DSSE
// envelope one level deeper than the raw-DSSE attArtifactType case.
type sigstoreBundle struct {
	DSSEEnvelope dsseEnvelope `json:"dsseEnvelope"`
}

type inTotoStatement struct {
	Subject       []inTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     slsaPredicate   `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// simpleSigning is the cosign simplesigning payload (the sig layer blob).
// critical.image.docker-manifest-digest binds the signature to a specific image.
type simpleSigning struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
	} `json:"critical"`
}

type slsaPredicate struct {
	BuildDefinition struct {
		ResolvedDependencies []struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata struct {
			StartedOn *time.Time `json:"startedOn"`
		} `json:"metadata"`
	} `json:"runDetails"`
}

// cosignBundle is the JSON shape of the dev.sigstore.cosign/bundle annotation.
type cosignBundle struct {
	Payload struct {
		LogIndex int64  `json:"logIndex"`
		LogID    string `json:"logID"`
	} `json:"Payload"`
}

// --- entry point -------------------------------------------------------------

// buildProvenance converts raw discovered bytes into a parsed Provenance.
func buildProvenance(raw RawArtifacts) Provenance {
	p := Provenance{
		SignaturePresent:   raw.SigPresent,
		AttestationPresent: raw.AttPresent,
	}
	if raw.SigPresent {
		extractFromSig(&p, raw.SigAnnotations)
	}
	if raw.AttPresent {
		switch raw.AttArtifactType {
		case inTotoArtifactType:
			extractFromRawInToto(&p, raw.AttLayerBytes)
		case bundleArtifactType:
			extractFromSigstoreBundle(&p, raw.AttLayerBytes)
		default:
			extractFromAtt(&p, raw.AttLayerBytes)
		}
	}
	return p
}

// --- sig extraction ----------------------------------------------------------

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
		var b cosignBundle
		if err := json.Unmarshal([]byte(bundleJSON), &b); err == nil && b.Payload.LogIndex > 0 {
			p.RekorLogIndex = b.Payload.LogIndex
		}
	}
}

const rekorBaseURL = "https://rekor.sigstore.dev"

// fetchRekorUUID fetches the Rekor transparency log UUID for the given log index.
// Returns "" on any error — Rekor is external and non-critical (fail-open).
func fetchRekorUUID(ctx context.Context, logIndex int64) string {
	return fetchRekorUUIDFromBase(ctx, rekorBaseURL, logIndex)
}

// fetchRekorUUIDFromBase is the testable core: it accepts a base URL so tests
// can substitute an httptest.Server without hitting the public Rekor instance.
func fetchRekorUUIDFromBase(ctx context.Context, baseURL string, logIndex int64) string {
	reqURL := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", baseURL, logIndex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()
	var entries map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return ""
	}
	for uuid := range entries {
		return uuid
	}
	return ""
}

// sigBoundDigest returns the image digest a simplesigning payload is bound to
// (critical.image.docker-manifest-digest), or "" if absent/unparseable.
func sigBoundDigest(sigLayerBytes []byte) string {
	var ss simpleSigning
	if err := json.Unmarshal(sigLayerBytes, &ss); err != nil {
		return ""
	}
	return ss.Critical.Image.DockerManifestDigest
}

// --- att extraction ----------------------------------------------------------

// extractFromRawInToto parses a buildkit-native in-toto statement (not DSSE-wrapped).
// The layer bytes are raw JSON — no envelope, no base64 encoding.
func extractFromRawInToto(p *Provenance, layerBytes []byte) {
	var stmt inTotoStatement
	if err := json.Unmarshal(layerBytes, &stmt); err != nil {
		return
	}
	p.PredicateType = stmt.PredicateType
	p.BuilderID = stmt.Predicate.RunDetails.Builder.ID
	p.BuildStartedOn = stmt.Predicate.RunDetails.Metadata.StartedOn
	for _, s := range stmt.Subject {
		if sha, ok := s.Digest["sha256"]; ok {
			p.Subjects = append(p.Subjects, s.Name+"@sha256:"+sha)
		}
	}
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if strings.HasPrefix(dep.URI, "git+") {
			p.SourceURI = strings.TrimPrefix(dep.URI, "git+")
			if commit, ok := dep.Digest["sha1"]; ok {
				p.SourceCommit = commit
			}
			break
		}
	}
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

	var stmt inTotoStatement
	if err := json.Unmarshal(decoded, &stmt); err != nil {
		return
	}

	p.PredicateType = stmt.PredicateType
	p.BuilderID = stmt.Predicate.RunDetails.Builder.ID
	p.BuildStartedOn = stmt.Predicate.RunDetails.Metadata.StartedOn

	for _, s := range stmt.Subject {
		if sha, ok := s.Digest["sha256"]; ok {
			p.Subjects = append(p.Subjects, s.Name+"@sha256:"+sha)
		}
	}

	// Source: prefer git+ dependency (standard SLSA); oci:// and other schemes are skipped.
	for _, dep := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if strings.HasPrefix(dep.URI, "git+") {
			p.SourceURI = strings.TrimPrefix(dep.URI, "git+")
			if commit, ok := dep.Digest["sha1"]; ok {
				p.SourceCommit = commit
			}
			break
		}
	}
}
