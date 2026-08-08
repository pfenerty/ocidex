#!/bin/sh
# Push build: tags images as sha-<short> and main.
# Per-image values come from step env: DOCKERFILE, IMAGE, optional TARGET,
# IMAGE_TITLE, IMAGE_DESCRIPTION.
# buildctl's exit code is captured in $rc and re-exited after writing Chains hints.
# Context is .buildctx (the commit tree, written by the prepare-build-context step),
# not the shared workspace — see spec.ts.
#
# No --export-cache/--import-cache: the registry build cache was measured (ocidex-2vr.3) at
# 85-96s of export per build for zero CACHED steps on import. The persistent buildkitd root
# (ocidex-2vr.2) supersedes it — it caches both within a run and across runs on the same node,
# at no export cost. Do not re-add these flags without re-measuring both sides.
SHORT_SHA=$(echo "$(params.revision)" | cut -c1-8)
VERSION="main-$SHORT_SHA"
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# build-arg:DATE must be identical for every image in the chain, or docker/Dockerfile's shared
# build-all stage re-runs its `go build` for each one instead of hitting CACHED (ocidex-2j2).
# prepare-build-context pins it to the commit's own timestamp; the wall-clock CREATED above
# still feeds the OCI labels/annotations, which are applied at export and do not affect the
# build cache. Fallback covers a workspace materialised before this file existed.
SOURCE_DATE=$(cat .buildctx.date 2>/dev/null) || SOURCE_DATE=""
if [ -z "$SOURCE_DATE" ]; then SOURCE_DATE="$CREATED"; fi

# OCI metadata is applied entirely via buildctl CLI (no Dockerfile LABELs):
#   --opt label:KEY=VALUE      -> per-platform image config labels (docker inspect).
#     label: is a dockerfile FRONTEND opt; as an image EXPORTER (--output) attribute
#     buildkit silently ignores it, which is why labels were previously missing.
#   annotation-index.KEY=VALUE -> OCI annotations on the image index (read by GHCR).
A=org.opencontainers.image
SRC=https://github.com/pfenerty/ocidex
ANN="annotation-index.$A.version=$VERSION"
ANN="$ANN,annotation-index.$A.revision=$(params.revision)"
ANN="$ANN,annotation-index.$A.created=$CREATED"
ANN="$ANN,annotation-index.$A.source=$SRC"
ANN="$ANN,annotation-index.$A.url=$SRC"
ANN="$ANN,annotation-index.$A.licenses=MIT"
ANN="$ANN,annotation-index.$A.authors=Patrick Fenerty"
ANN="$ANN,annotation-index.$A.title=$IMAGE_TITLE"
ANN="$ANN,annotation-index.$A.description=$IMAGE_DESCRIPTION"

TARGET_OPT=""
if [ -n "$TARGET" ]; then TARGET_OPT="--opt target=$TARGET"; fi

buildctl-daemonless.sh build \
  --frontend dockerfile.v0 \
  --local context=.buildctx \
  --local dockerfile=.buildctx \
  --opt filename="$DOCKERFILE" \
  $TARGET_OPT \
  --opt platform=linux/amd64 \
  --opt build-arg:VERSION="$VERSION" \
  --opt build-arg:COMMIT="$(params.revision)" \
  --opt build-arg:DATE="$SOURCE_DATE" \
  --opt "label:$A.version=$VERSION" \
  --opt "label:$A.revision=$(params.revision)" \
  --opt "label:$A.created=$CREATED" \
  --opt "label:$A.source=$SRC" \
  --opt "label:$A.url=$SRC" \
  --opt "label:$A.licenses=MIT" \
  --opt "label:$A.authors=Patrick Fenerty" \
  --opt "label:$A.title=$IMAGE_TITLE" \
  --opt "label:$A.description=$IMAGE_DESCRIPTION" \
  --opt attest:provenance=mode=max \
  --opt attest:sbom= \
  --metadata-file /tmp/buildctl-metadata.json \
  --output "type=image,\"name=$IMAGE:sha-$SHORT_SHA,$IMAGE:main\",push=true,attestation-manifest-referrers=true,$ANN"
rc=$?

# Tekton Chains build-subject hints: record the pushed image ref + digest so Chains
# attests this run produced this image. Best-effort; never masks buildctl's exit.
if [ "$rc" -eq 0 ] && [ -n "$CHAINS_IMAGE_URL_PATH" ]; then
  DIGEST=$(sed -n 's/.*"containerimage.digest": *"\([^"]*\)".*/\1/p' /tmp/buildctl-metadata.json | head -1)
  printf '%s' "$IMAGE" > "$CHAINS_IMAGE_URL_PATH"
  printf '%s' "$DIGEST" > "$CHAINS_IMAGE_DIGEST_PATH"
fi
exit "$rc"
