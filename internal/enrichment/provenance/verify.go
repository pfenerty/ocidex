package provenance

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// applyVerification sets p.Verified based on the registry trust configuration.
// mode "public_key" with a non-empty pemKey triggers ECDSA verification of both
// the simplesigning sig and the DSSE attestation. Any other mode leaves Verified nil.
func applyVerification(p *Provenance, raw RawArtifacts, mode, pemKey string) {
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
		verified = verified && verifySig(pubkey, sigBase64, raw.SigLayerBytes)
	}
	if raw.AttPresent {
		var env dsseEnvelope
		if err := json.Unmarshal(raw.AttLayerBytes, &env); err == nil {
			verified = verified && verifyDSSE(pubkey, env)
		}
	}
	p.Verified = &verified
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
