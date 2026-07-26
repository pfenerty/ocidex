# ADR 0037: Cosign-Delegated Provenance Verification

**Status:** Accepted (supersedes ADR-0032)
**Date:** 2026-07-26

## Context

ADR-0032 explicitly avoided pulling in the cosign SDK to keep the provenance enricher
free of the sigstore dependency tree and Fulcio/CT-log trust coupling, implementing
verification with `crypto/ecdsa` + `crypto/x509` only. Epic `ocidex-82g` reversed that
decision without a documentation commit: `git log --oneline 245d6e3..a27dc0d -- docs/`
returns nothing, even though the epic added a keyless (Fulcio/Rekor) trust tier, a fifth
signing-status value, and a live Rekor lookup. ADR-0032 now describes a system that no
longer exists. This ADR records what actually shipped and why the dependency-weight
tradeoff was reversed.

## Decision

### Dependency-weight reversal

`internal/enrichment/provenance/verify.go` and `keyless.go` now delegate directly to
`github.com/sigstore/cosign/v2` (`cosign.CheckOpts`, image-signature and
image-attestation verification) and `github.com/sigstore/sigstore-go` (TUF-fetched
trusted root for Fulcio/Rekor material). `go list -deps ./cmd/ocidex` reports **786**
modules. Neither `crypto/ecdsa` nor `crypto/x509` is imported anywhere in the
`provenance` package anymore.

This reverses ADR-0032's core premise. The reversal was the right call: digest-binding
claim verification (`SimpleClaimVerifier` / `IntotoSubjectClaimVerifier`) and
Fulcio/Rekor keyless verification are not reasonably hand-rollable without
re-implementing large parts of cosign's own verify pipeline. Delegating to cosign's
verifier is the reference implementation for exactly this check, and doing so deleted
the hand-rolled simplesigning/DSSE parsing that ADR-0032's approach required. The
dependency-weight cost ADR-0032 avoided is accepted as the price of correctness and of
supporting the keyless tier through the same pipeline as the public-key tier.

### Trust tiers (corrected)

`registry.verification_mode` is a 3-value column (`none | public_key | keyless`, CHECK
constraint in `db/migrations/00035_registry_trust.sql`), resolved into a `trust.Config`
(`internal/trust/trust.go`) by `RegistryService.BuildTrustLookup`
(`internal/service/registry.go`), which caches resolved config in-process for 30s
(`resolverCacheTTL`) — not "left to the database connection pool" per enrichment call,
as ADR-0032 stated.

| Mode | Config | Verification | Status on success |
|---|---|---|---|
| `none` (default) | — | none — discovery still runs, presence is recorded | `signed` |
| `public_key` | `trust_anchor_pem` | `cosign.CheckOpts{SigVerifier: ecdsaVerifier}` | `verified` |
| `keyless` | `trust_identity` + `trust_issuer` | `cosign.CheckOpts{TrustedMaterial, Identities}` — Fulcio cert match + offline Rekor SET check | `verified` |

Two corrections to ADR-0032's tier table:

1. There is no `display` mode value. What ADR-0032 called "Tier 1 / display" is simply
   what `none` does today — the enricher always fetches and records presence.
2. Mode never gates the enricher itself. `Enricher.CanEnrich` only checks artifact type
   and digest presence; `verification_mode` only determines whether `applyTrust` runs a
   cryptographic check. ADR-0032's "Tier 0: skip enricher" row was never accurate for
   the shipped code.

Keyless verification is no longer reserved for a future ADR (ADR-0032 pointed at
ADR-0034; ADR-0033/0034/0035 do not mention keyless, Fulcio, or cosign) — it shipped in
`ocidex-82g` as `applyKeylessVerification` (`keyless.go`), using `sigstore-go`'s TUF
client for the public-good trusted root, cached for 24h (`trustedRootCacheTTL`).

### Signing status (five values, not four)

`SigningStatus` (`internal/enrichment/provenance/status.go`) and the mirrored
`signing_status(jsonb)` SQL function (`db/migrations/00049_signing_status_function.sql`)
return:

- `artifact_missing` — a pre-verification existence check found the digest no longer
  resolves in the registry
- `unsigned` — no signature or attestation referrers found
- `signed` — referrers found, no cryptographic check performed (mode `none`, or a raw
  in-toto attestation with no cosign signature)
- `verified` — a cryptographic check actually ran and passed (see `ocidex-goh.1`: a raw
  in-toto attestation alone no longer produces a false `verified`)
- `verification_failed` — a check ran and failed, or a referrer payload was present but
  unparseable (fail-closed)

### Rekor UUID is now fetched

ADR-0032 stated "Rekor UUID is not fetched; only the `logIndex` annotation ... is
recorded. Rekor lookup is deferred." That is no longer true: `fetchRekorUUID`
(`internal/enrichment/provenance/parse.go`) makes a live HTTP call to Rekor's
`/api/v1/log/entries?logIndex=` endpoint whenever `RekorLogIndex > 0`, populating
`RekorUUID` for display. This is unrelated to trust decisions — it's a display
convenience. Keyless SET verification itself remains offline, using `sigstore-go`'s
TUF-fetched trusted material, matching ADR-0032's original offline-verification intent.

## Consequences

- The fail-closed rule from ADR-0032 for unparseable referrer payloads is unchanged.
- Trust config resolution is cached in-process for 30s, not re-fetched from the database
  on every enrichment call.
- Dependency surface grew substantially (786 transitive modules via cosign/sigstore-go);
  accepted as the cost of one correct, shared verify pipeline instead of two hand-rolled
  ones that could not support keyless verification.
- A periodic reverifier (`internal/enrichment/reverify.go`,
  `internal/enrichment/provenance_drift.go`) re-checks stored provenance for drift. Its
  correctness is tracked separately (`ocidex-goh.2`, `.7`, `.10`) and is out of scope for
  this ADR — its existence is noted here only for completeness of the provenance
  subsystem's file map.

## Key Files

- `internal/enrichment/provenance/verify.go` — `applyVerification` (public-key tier)
- `internal/enrichment/provenance/keyless.go` — `applyKeylessVerification` (keyless
  tier), shared `verifyOCISignature`/`verifyOCIAttestation`
- `internal/enrichment/provenance/status.go` — `SigningStatus` (five values, the single
  Go source of truth)
- `internal/enrichment/provenance/parse.go` — `fetchRekorUUID`
- `internal/trust/trust.go` — `trust.Config`
- `internal/service/registry.go` — `BuildTrustLookup`
- `db/migrations/00035_registry_trust.sql` — `verification_mode` CHECK constraint
- `db/migrations/00049_signing_status_function.sql` — `signing_status(jsonb)` SQL mirror
- `docs/adr/0032-provenance-verification.md` — superseded by this ADR

## Superseded

This ADR supersedes [ADR-0032](0032-provenance-verification.md), whose "no cosign SDK"
decision, three-tier table (with a `display` mode that no longer exists and a `keyless`
row marked reserved), four-value status enum, and "Rekor UUID not fetched" claim no
longer match the shipped implementation.
