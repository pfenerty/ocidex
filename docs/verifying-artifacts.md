# Verifying ocidex artifacts

ocidex container images are published to `ghcr.io/pfenerty/ocidex-*`
(`api`, `scanner-worker`, the per-enricher workers, `vuln-worker`, `web`, `operator`, `cli`) with build
provenance and SBOMs you can verify before running them.

## What each image carries

| Artifact | Producer | Signed | Where |
|---|---|---|---|
| SLSA provenance (`mode=max`) + SBOM | buildkit (build time) | no | embedded in the image index |
| Signed SLSA provenance + image signature | Tekton Chains (cluster) | **yes** — cosign x509 + Rekor | attached to the image in the registry |

The signing public key is published in this repo: [`cosign.pub`](../cosign.pub) — or fetch it
directly:

```bash
curl -fsSL https://raw.githubusercontent.com/pfenerty/ocidex/main/cosign.pub -o cosign.pub
```

Always verify by **immutable digest**. Get one with:

```bash
IMAGE=ghcr.io/pfenerty/ocidex-api
REF="$IMAGE@$(docker buildx imagetools inspect "$IMAGE:main" --format '{{.Manifest.Digest}}')"
```

## 1. Verify the signature + signed provenance (recommended)

```bash
# Tekton Chains image signature (cosign simplesigning)
cosign verify --key cosign.pub "$REF"

# Signed SLSA provenance attestation (Chains emits SLSA v1.0, so use slsaprovenance1;
# the bare `slsaprovenance` alias is SLSA v0.2 and will not match)
cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$REF" \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

## Helm charts

The released charts (`ocidex`, `ocidex-operator`, `ocidex-k8s-agent` under
`oci://ghcr.io/pfenerty/charts`) carry the same Tekton Chains signature and signed SLSA
provenance as the images, from charts released after ocidex-tkn9.10. They have no buildkit
provenance or SBOM (they are not container images). Verify by digest, the same way:

```bash
V=0.1.0
CHART=ghcr.io/pfenerty/charts/ocidex
REF="$CHART@$(crane digest "$CHART:$V")"
cosign verify --key cosign.pub "$REF"
cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$REF" >/dev/null && echo "provenance ok"
```

`helm pull oci://ghcr.io/pfenerty/charts/ocidex@<digest>` installs exactly the artifact you
verified.

## 2. Inspect buildkit provenance + SBOM (no key needed)

```bash
docker buildx imagetools inspect "$REF" --format '{{ json .Provenance }}'
docker buildx imagetools inspect "$REF" --format '{{ json .SBOM }}'
```

## 3. Transparency log (Rekor)

Every Chains signature is recorded in the public Rekor log:

```bash
rekor-cli search --sha "${REF#*@}"
```

You can also read the `chains.tekton.dev/transparency` annotation on the producing
PipelineRun (it links the exact Rekor entry).

## Status / prerequisites

The signed, image-attached verification in **step 1** depends on two cluster-side pieces (see
the `homelab` repo) and applies to images built after they are in place:

- Tekton Chains **OCI storage** enabled with a registry-push credential on the chains
  controller.
- ocidex's build tasks declaring the image as a Chains subject (the `ChainsImage`/`IMAGES`
  result). Until that is on `main`, use **step 2** (buildkit provenance/SBOM, available on
  every image today) and **step 3** (Rekor) for the run-level signed provenance.
