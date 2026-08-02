---
status: "accepted"
date: 2026-08-02
decision-makers: Patrick Fenerty
---

# Non-container artifact identity

## Context and Problem Statement

The ingest pipeline is already type-agnostic: `resolveArtifact`
(`internal/service/sbom.go:87`) upserts an `artifact` row with whatever
`metadata.component.type` the BOM declares, and the container-specific rules there and in
`validateContainerRequired` are correctly gated on `type == container`. ADR-039 supplied
the missing owner for a non-registry artifact — a `namespace` reached through an `upload`
source. What is still missing is *identity*.

A container SBOM carries its own identity. Syft names the subject
`docker.io/ubuntu@sha256:…`, so `resolveArtifact` can split the name into a stable
artifact name plus a digest, and that digest is both the reproducibility anchor and the
idempotency key (`00006_sbom_digest_unique.sql`).

An SBOM over a directory of built binaries carries nothing comparable. `syft
dir:.sbom-bins` — the form this repo already uses in `.tektonic/jobs/_dep-scan.ts`,
because cataloguing built binaries avoids the go.sum phantom-version problem — emits a
`metadata.component` that describes *the directory*: type `file`, name `.sbom-bins`, no
version, no purl. Ingesting that today produces an artifact named after a scratch
directory, with no digest, that cannot be linked to anything and collides with every
other build that used the same directory name.

So: where does a non-container artifact's identity come from, and what is its digest?

## Decision Drivers

* Nothing in a `syft dir:` BOM identifies the artifact — inference has no input to work
  from.
* The `sbom.digest` UNIQUE index is the idempotency guarantee for the whole ingest path
  (`Ingest` short-circuits on `GetSBOMByDigest` before opening a transaction). A
  non-container path that leaves `digest` NULL silently opts out of it, and re-pushing
  from CI would duplicate rows.
* Container ingest rules are in production and must not change shape.
* ADR-041 will derive artifact relationships by matching an image SBOM's components
  against tracked artifacts, so an uploaded artifact's identity has to be expressible in
  the same vocabulary components use — a purl.

## Considered Options

* Infer identity from the BOM (`metadata.component`, main-module heuristics)
* Caller-declared identity at upload, digest = sha256 of the artifact file
* Caller-declared identity, digest = sha256 of the SBOM document
* Caller-declared identity, no digest for non-container artifacts

## Decision Outcome

Chosen option: **caller-declared identity at upload, with digest = the sha256 of the
artifact file**, because it is the only option with an actual input, and it is the one
that keeps the digest column meaning the same thing it already means.

**Identity is declared, not inferred.** The uploader states subject type, name, group,
purl and version. These are carried on `IngestParams` and take precedence over
`bom.Metadata.Component` — which is exactly the contract the struct's doc comment already
declares ("Fields take precedence over BOM-extracted values when set"), so this extends
an existing rule rather than introducing one. When no override is supplied, BOM
extraction behaves as it does today, so container scanning is untouched.

**Digest is the sha256 of the artifact file**, not of the SBOM. This mirrors the
container rule: `sbom.digest` identifies *the thing described*, never the description of
it. Two SBOMs of the same binary produced by different scanner versions are the same
subject and must collapse to one row; an SBOM regenerated over a rebuilt binary is a
different subject and must not.

The producing side computes it — `ocidex-cli sbom push --artifact-file ./bin/ocidex`
hashes the file locally and sends the result. The server never sees the binary, only the
hash, which keeps upload payloads to the SBOM alone.

**Digest is required for a non-container upload**, alongside subject type, name and
version. `validateUploadRequired` sits beside `validateContainerRequired` and applies to
non-container subjects arriving on an `upload` source; the container branch is untouched.

**Purl is the identity that travels.** Where the caller can supply one
(`pkg:golang/github.com/pfenerty/ocidex@v1.2.3`), it is stored on `artifact.purl`, which
is what ADR-041's relationship matching keys on. It is not mandatory — an artifact with
no meaningful purl is still trackable via the `(type, name, group_name)` tuple, which is
ADR-019's fallback rule and ADR-041's.

### Consequences

* Good, because the `sbom.digest` UNIQUE index keeps working unchanged. Re-running a CI
  push for an unchanged binary is a no-op rather than a duplicate, on exactly the same
  code path containers already use.
* Good, because `resolveArtifact` gains parameter precedence rather than a second
  identity mechanism. There remains one artifact-resolution function.
* Good, because a declared purl makes uploaded artifacts matchable against image SBOM
  components without a stored link table (ADR-041).
* Bad, because identity correctness now depends on the caller. A CI job that declares the
  wrong name creates a wrong artifact, and nothing server-side can detect it. Mitigated
  by `ocidex-cli` computing the digest from the file it was pointed at, so the one field
  that is expensive to get wrong is not typed by a human.
* Bad, because the server cannot verify the digest belongs to the SBOM — it never sees
  the artifact. This is accepted: the same is true of container ingest, where the digest
  is taken from the scanner's output on trust. Provenance verification (ADR-037) is the
  layer that answers "should I believe this", and it is deliberately separate.
* **The pre-transaction idempotency check must learn about params.**
  `extractDigestFromBOM` (`internal/service/sbom.go:891`) reads only
  `metadata.component`, so for an upload it returns `""` and the early
  `GetSBOMByDigest` short-circuit is skipped. Ingest still converges — the UNIQUE index
  is the backstop — but the duplicate is only caught at INSERT, after a transaction and
  a full component decomposition. The digest check must consult `params.Digest` first.
* Neutral: uploads with no declared purl are still ingestible and still visible; they
  just participate in relationship matching by tuple rather than purl.

### Confirmation

* `validateUploadRequired` rejects a non-container upload missing subject type, name,
  version or digest, with a `ValidationError` naming the missing fields — same shape as
  `validateContainerRequired`.
* Unit tests in `internal/service/sbom_ingest_test.go` beside the existing
  `TestResolveArtifact_NonContainer`: params override `metadata.component`; a container
  BOM with no params behaves exactly as before.
* An integration test pushes the same binary SBOM twice and asserts one `sbom` row.
* Container behaviour is confirmed unchanged by the existing
  `TestResolveArtifact_Container*` tests passing untouched.

## Pros and Cons of the Options

### Infer identity from the BOM

* Good, because it requires nothing of the caller.
* Bad, because there is nothing to infer from. A `syft dir:` subject component is the
  scratch directory; its name is a build-layout detail, not an identity.
* Bad, because any heuristic (e.g. read the Go main module from components) is
  ecosystem-specific and silently wrong for every artifact it was not written for. It
  fails by producing a plausible wrong answer.

### Caller-declared identity, digest = sha256 of the artifact file

* Good, because `sbom.digest` keeps its existing meaning — the identity of the subject —
  so idempotency, dedup and every digest-keyed lookup work without special-casing.
* Good, because the value is cheap and unambiguous for the producer to compute; CI
  already has the file in hand.
* Bad, because it requires the client to have the artifact, not just its SBOM. Accepted:
  the CI job that generates the SBOM is by construction the job that built the binary.

### Caller-declared identity, digest = sha256 of the SBOM document

* Good, because it needs no extra input beyond the upload payload.
* Bad, because it breaks the invariant. Re-scanning one binary with an upgraded syft
  yields a different document hash and therefore a second "artifact version" that does
  not exist. Idempotency would key on the description rather than the thing.

### Caller-declared identity, no digest

* Good, because it is the smallest change.
* Bad, because the UNIQUE index is partial (`WHERE digest IS NOT NULL`), so every upload
  bypasses idempotency entirely and each CI run appends a duplicate SBOM.
* Bad, because it splits the ingest path in two: one kind of SBOM that dedups and another
  that does not.

## More Information

* ADR-039 — namespace/source model; supplies the owner an uploaded artifact attaches to.
* ADR-019 — diff identity model; source of the purl-base-then-tuple fallback reused here.
* ADR-037 — provenance verification; the separate layer answering trust, not identity.
* `00006_sbom_digest_unique.sql` — the partial UNIQUE index this decision preserves.
* `internal/service/sbom.go` — `IngestParams` (:35), `resolveArtifact` (:87),
  `validateContainerRequired` (:229), `extractDigestFromBOM` (:891).
* Implementation: `ocidex-0gp.2` (params + validation), `ocidex-0gp.3` (source binding),
  `ocidex-0gp.4` (`ocidex-cli sbom push`).
