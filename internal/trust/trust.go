// Package trust defines the per-host signature verification configuration
// shared by internal/service (which resolves it from stored registry
// settings) and internal/enrichment/provenance (which consumes it to verify
// signatures). It exists as a leaf package so both sides can depend on one
// type without either importing the other.
package trust

// Config is the per-host signature verification configuration resolved from
// a registry's stored trust settings.
type Config struct {
	Mode         string // "none" | "public_key" | "keyless"
	PublicKeyPEM string
	Identity     string // regex matched against the Fulcio cert SAN (keyless only)
	Issuer       string // exact OIDC issuer URL (keyless only)
}
