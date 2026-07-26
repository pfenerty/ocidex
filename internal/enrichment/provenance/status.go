package provenance

// SigningStatus derives the terminal signing status for p — the same value
// the signing_status(jsonb) SQL function computes from the enrichment's raw
// JSON. Keep the two in sync: this is the ONLY Go copy.
func SigningStatus(p Provenance) string {
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
