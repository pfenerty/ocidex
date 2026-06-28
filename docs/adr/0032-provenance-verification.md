# ADR 0032: Provenance Verification Trust Model

**Status:** Accepted  
**Date:** 2026-06-27

## Context

Tekton Chains signs every `apko-cicd`/`ocidex` image at build time, producing two OCI referrer artifacts per image: a cosign simplesigning signature (`application/vnd.dev.cosign.artifact.sig.v1+json`) and a SLSA DSSE attestation (`application/vnd.dsse.envelope.v1+json`), with the Rekor log entry recorded in both annotations. OCIDex needed to surface this data and optionally verify it, without pulling in the cosign SDK (which drags in sigstore dependencies and ties verification to Fulcio/CT-log trust).

## Decision

### Trust tiers per registry

Verification mode is determined per registry by a `trust_anchor_pem` column in the `registries` table. The resolver (`service.BuildTrustLookup`) returns a `(mode, pemKey)` pair:

| Tier | `trust_anchor_pem` | Mode | Outcome |
|------|--------------------|------|---------|
| 0 | — | `none` | Skip enricher (OCI referrers not supported or disabled) |
| 1 | empty | `display` | Fetch artifacts, record presence, badge `signed` |
| 2 | PEM key present | `public_key` | Fetch + ECDSA verify, badge `verified` or `verification_failed` |
| 3 | (future) | `keyless` | Fulcio/sigstore-go (reserved; atd.15) |

### Signing-status values

Four values are stored in `enrichment.data.signingStatus` and surfaced in the API:

- `unsigned` — no signature or attestation referrers found
- `signed` — referrers found, no anchor configured (Tier 1)
- `verified` — ECDSA verification passed against registry PEM anchor (Tier 2)
- `verification_failed` — anchor present but verification failed or attestation unparseable

### Discovery

`remote.Referrers()` (OCI 1.1 Referrers API) is tried first. If the registry returns `405` or an empty list, the enricher falls back to the cosign tag scheme (`sha256-<HEX>.sig` / `sha256-<HEX>.att`). The discovery method is recorded in the enrichment result.

### Verification (Tier 2)

Verification uses `crypto/ecdsa` + `crypto/x509` only — no cosign or sigstore SDK. Two digest-binding checks are enforced to prevent signature transplant:

1. **Simplesigning:** `critical.image.docker-manifest-digest` in the signature payload must equal `ref.Digest`.
2. **DSSE attestation:** at least one `in-toto` subject digest value must equal `ref.Digest`.

If a referrer artifact is present but its payload cannot be parsed, the status is set to `verification_failed` — not `signed`. This fail-closed rule ensures an attacker cannot smuggle an opaque blob to bypass verification.

### Trust resolver caching

`BuildTrustLookup` returns a closure over a `RegistryService`. Registry rows are fetched per enrichment call; caching is left to the database connection pool. The pattern mirrors `BuildInsecureHostLookup`.

### ghcr.io/pfenerty anchor

The P-256 ECDSA public key from `apko-cicd/cosign.pub` is stored as `trust_anchor_pem` on the `ghcr.io/pfenerty` registry row. It is configured via the admin UI (ADR-010 registry trust config) or the API, not hardcoded.

## Consequences

- Rekor UUID is not fetched; only the `logIndex` annotation (if present) is recorded. Rekor lookup is deferred.
- Keyless (Fulcio) verification is not implemented; the `keyless` mode value is reserved for ADR-034.
- Trust anchors are per-registry configuration, not per-image policy.
- The `verification_failed` badge (danger styling) is distinct from `unsigned` and `signed` so operators can distinguish a compromised image from an unsigned one.
- The enricher runs only for `container` artifacts with a non-empty digest (`CanEnrich` gate).

## Key Files

- `internal/enrichment/provenance/provenance.go` — `Enricher`, `RawArtifacts`, discovery orchestration
- `internal/enrichment/provenance/parse.go` — simplesigning + DSSE payload parsing
- `internal/enrichment/provenance/verify.go` — `applyVerification`, ECDSA verify, digest binding
- `internal/service/registry.go` — `BuildTrustLookup`, `BuildInsecureHostLookup`
- `db/migrations/` — `trust_anchor_pem` column on `registries`
- `docs/adr/0026-pluggable-enricher.md` — Enricher interface and Dispatcher
