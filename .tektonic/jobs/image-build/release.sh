#!/bin/sh
# Release build: tags images with semver aliases from the git tag name.
# latest is only added for stable releases (no hyphen in tag).
# Per-image values come from step env: DOCKERFILE, IMAGE, optional TARGET,
# IMAGE_TITLE, IMAGE_DESCRIPTION.
# buildctl's exit code is captured in $rc and re-exited after writing Chains hints.
TAG="$(params.source-branch)"
TAG="${TAG#refs/tags/}"
BARE="${TAG#v}"
MAJOR=$(echo "$BARE" | cut -d. -f1)
MINOR=$(echo "$BARE" | cut -d. -f2)

NAMES="$IMAGE:$TAG,$IMAGE:$MAJOR.$MINOR,$IMAGE:$MAJOR"
if ! echo "$TAG" | grep -q '-'; then
  NAMES="$NAMES,$IMAGE:latest"
fi
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# OCI metadata is applied entirely via buildctl CLI (no Dockerfile LABELs):
#   --opt label:KEY=VALUE      -> per-platform image config labels (docker inspect).
#     label: is a dockerfile FRONTEND opt; as an image EXPORTER (--output) attribute
#     buildkit silently ignores it, which is why labels were previously missing.
#   annotation-index.KEY=VALUE -> OCI annotations on the image index (read by GHCR).
A=org.opencontainers.image
SRC=https://github.com/pfenerty/ocidex
ANN="annotation-index.$A.version=$TAG"
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
  --local context=. \
  --local dockerfile=. \
  --opt filename="$DOCKERFILE" \
  $TARGET_OPT \
  --opt platform=linux/amd64,linux/arm64 \
  --opt build-arg:VERSION="$TAG" \
  --opt build-arg:COMMIT="$(params.revision)" \
  --opt build-arg:DATE="$CREATED" \
  --opt "label:$A.version=$TAG" \
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
  --export-cache "type=registry,ref=$IMAGE:buildcache,mode=max,image-manifest=true,oci-mediatypes=true" \
  --import-cache "type=registry,ref=$IMAGE:buildcache" \
  --metadata-file /tmp/buildctl-metadata.json \
  --output "type=image,\"name=$NAMES\",push=true,attestation-manifest-referrers=true,$ANN"
rc=$?

# Tekton Chains build-subject hints: record the pushed image ref + digest so Chains
# attests this run produced this image. Best-effort; never masks buildctl's exit.
if [ "$rc" -eq 0 ] && [ -n "$CHAINS_IMAGE_URL_PATH" ]; then
  DIGEST=$(sed -n 's/.*"containerimage.digest": *"\([^"]*\)".*/\1/p' /tmp/buildctl-metadata.json | head -1)
  printf '%s' "$IMAGE" > "$CHAINS_IMAGE_URL_PATH"
  printf '%s' "$DIGEST" > "$CHAINS_IMAGE_DIGEST_PATH"
fi
exit "$rc"
