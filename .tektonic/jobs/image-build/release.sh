#!/bin/sh
# Release build: tags images with semver aliases from the git tag name.
# latest is only added for stable releases (no hyphen in tag).
# Per-image values come from step env: DOCKERFILE, IMAGE, and optional TARGET.
# buildctl is the final command so its exit code is what synth captures.
TAG="$(params.source-branch)"
TAG="${TAG#refs/tags/}"
BARE="${TAG#v}"
MAJOR=$(echo "$BARE" | cut -d. -f1)
MINOR=$(echo "$BARE" | cut -d. -f2)

NAMES="$IMAGE:$TAG,$IMAGE:$MAJOR.$MINOR,$IMAGE:$MAJOR"
if ! echo "$TAG" | grep -q '-'; then
  NAMES="$NAMES,$IMAGE:latest"
fi

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
  --opt build-arg:DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --opt attest:provenance=mode=max \
  --opt attest:sbom= \
  --output "type=image,\"name=$NAMES\",push=true,attestation-manifest-referrers=true"
