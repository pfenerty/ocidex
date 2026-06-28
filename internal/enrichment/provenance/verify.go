package provenance

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// applyVerification sets p.Verified based on the registry trust configuration.
// mode "public_key" with a non-empty pemKey triggers ECDSA verification of both
// the simplesigning sig and the DSSE attestation. Any other mode leaves Verified nil.
//
// Verification requires not only a valid signature against the trusted key but also
// that the signed payload is bound to imageDigest (the artifact being enriched):
// the simplesigning critical.image.docker-manifest-digest and at least one DSSE
// in-toto subject digest must equal imageDigest. This prevents transplanting a valid
// signature from a different image signed by the same key.
func applyVerification(p *Provenance, raw RawArtifacts, mode, pemKey, imageDigest string) {
	if mode != "public_key" || pemKey == "" {
		return
	}
	if !raw.SigPresent && !raw.AttPresent {
		return
	}
	pubkey, err := parsePEMPublicKey(pemKey)
	if err != nil {
		return
	}
	verified := true
	if raw.SigPresent {
		sigBase64 := raw.SigAnnotations["dev.cosignproject.cosign/signature"]
		ok := verifySig(pubkey, sigBase64, raw.SigLayerBytes) &&
			sigBoundDigest(raw.SigLayerBytes) == imageDigest
		verified = verified && ok
	}
	if raw.AttPresent && raw.AttArtifactType != inTotoArtifactType {
		// An asserted DSSE attestation that cannot be parsed or verified must fail,
		// not be silently skipped. Raw in-toto atts (buildkit-native) carry no
		// envelope signature and are excluded from cryptographic verification.
		var env dsseEnvelope
		ok := json.Unmarshal(raw.AttLayerBytes, &env) == nil &&
			verifyDSSE(pubkey, env) &&
			subjectsBindTo(p.Subjects, imageDigest)
		verified = verified && ok
	}
	p.Verified = &verified
}

// subjectsBindTo reports whether any parsed subject ("name@sha256:hex") references
// imageDigest (e.g. "sha256:hex").
func subjectsBindTo(subjects []string, imageDigest string) bool {
	for _, s := range subjects {
		if i := strings.LastIndex(s, "@"); i != -1 && s[i+1:] == imageDigest {
			return true
		}
	}
	return false
}

func parsePEMPublicKey(pemKey string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return ecPub, nil
}

// verifySig verifies a cosign simplesigning signature.
// The signature is ASN.1 DER ECDSA over sha256(payload).
func verifySig(pubkey *ecdsa.PublicKey, sigBase64 string, payload []byte) bool {
	if sigBase64 == "" || len(payload) == 0 {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pubkey, h[:], sig)
}

// verifyDSSE verifies a DSSE envelope signature using the DSSE PAE format.
// PAE = "DSSEv1 <typeLen> <type> <bodyLen> <body>"
func verifyDSSE(pubkey *ecdsa.PublicKey, env dsseEnvelope) bool {
	if len(env.Signatures) == 0 {
		return false
	}
	rawPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return false
	}
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(env.PayloadType), env.PayloadType, len(rawPayload))
	pae := append([]byte(prefix), rawPayload...)
	h := sha256.Sum256(pae)
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(pubkey, h[:], sig) {
			return true
		}
	}
	return false
}
