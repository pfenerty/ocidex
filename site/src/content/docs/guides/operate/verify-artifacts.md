---
title: Verify release artifacts
description: Check the signatures, provenance and SBOMs of OCIDex's images and charts.
sidebar:
  order: 12
---

OCIDex's images (`ghcr.io/pfenerty/ocidex-*`) and Helm charts (`oci://ghcr.io/pfenerty/charts`) are
signed, and carry build provenance you can check before you run them.

| Artifact | Made by | Signed | Where |
| --- | --- | --- | --- |
| SLSA provenance and an SBOM | buildkit, at build time | No | In the image index |
| An image signature and signed SLSA provenance | Tekton Chains | **Yes**: cosign, recorded in Rekor | Attached to the image in the registry |

The public key is in the repository as
[`cosign.pub`](https://github.com/pfenerty/ocidex/blob/main/cosign.pub):

```sh
curl -fsSL https://raw.githubusercontent.com/pfenerty/ocidex/main/cosign.pub -o cosign.pub
```

Always verify by **digest**, never by tag:

```sh
IMAGE=ghcr.io/pfenerty/ocidex-api
REF="$IMAGE@$(crane digest "$IMAGE:<version>")"
```

## Verify the signature and provenance

```sh
cosign verify --key cosign.pub "$REF"

# Chains emits SLSA v1.0, so use slsaprovenance1. The bare "slsaprovenance" type is v0.2.
cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$REF" \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

## Helm charts

The released charts carry the same signature and signed provenance. They have no buildkit
provenance or SBOM, since they aren't images.

```sh
CHART=ghcr.io/pfenerty/charts/ocidex
REF="$CHART@$(crane digest "$CHART:<version>")"
cosign verify --key cosign.pub "$REF"
cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$REF" >/dev/null && echo "provenance ok"
```

`helm pull oci://ghcr.io/pfenerty/charts/ocidex@<digest>` then installs exactly what you verified.

## Inspect the build provenance and SBOM

No key is needed for buildkit's:

```sh
docker buildx imagetools inspect "$REF" --format '{{ json .Provenance }}'
docker buildx imagetools inspect "$REF" --format '{{ json .SBOM }}'
```

## The transparency log

Every signature is recorded in the public Rekor log:

```sh
rekor-cli search --sha "${REF#*@}"
```
