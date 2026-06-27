#!/bin/sh
# Push build: tags images as sha-<short> and main.
# Per-image values come from step env: DOCKERFILE, IMAGE, and optional TARGET.
# buildctl is the final command so its exit code is what synth captures.
SHORT_SHA=$(echo "$(params.revision)" | cut -c1-8)
VERSION="main-${SHORT_SHA}"

TARGET_OPT=""
if [ -n "$TARGET" ]; then TARGET_OPT="--opt target=$TARGET"; fi

buildctl-daemonless.sh build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --opt filename="$DOCKERFILE" \
  $TARGET_OPT \
  --opt platform=linux/amd64,linux/arm64 \
  --opt build-arg:VERSION="$VERSION" \
  --opt build-arg:COMMIT="$(params.revision)" \
  --opt build-arg:DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --opt attest:provenance=mode=max \
  --opt attest:sbom= \
  --export-cache "type=registry,ref=$IMAGE:buildcache,mode=max,image-manifest=true,oci-mediatypes=true" \
  --import-cache "type=registry,ref=$IMAGE:buildcache" \
  --output "type=image,\"name=$IMAGE:sha-$SHORT_SHA,$IMAGE:main\",push=true,attestation-manifest-referrers=true"
