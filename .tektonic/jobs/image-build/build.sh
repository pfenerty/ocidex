#!/bin/sh
# Push build: tags images as sha-<short> and main.
# Per-image values come from step env: DOCKERFILE, IMAGE, and optional TARGET.
# buildctl's exit code is captured in $rc and re-exited after writing Chains hints.
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
  --metadata-file /tmp/buildctl-metadata.json \
  --output "type=image,\"name=$IMAGE:sha-$SHORT_SHA,$IMAGE:main\",push=true,attestation-manifest-referrers=true"
rc=$?

# Tekton Chains build-subject hints: record the pushed image ref + digest so Chains
# attests this run produced this image. Best-effort; never masks buildctl's exit.
if [ "$rc" -eq 0 ] && [ -n "$CHAINS_IMAGE_URL_PATH" ]; then
  DIGEST=$(sed -n 's/.*"containerimage.digest": *"\([^"]*\)".*/\1/p' /tmp/buildctl-metadata.json | head -1)
  printf '%s' "$IMAGE" > "$CHAINS_IMAGE_URL_PATH"
  printf '%s' "$DIGEST" > "$CHAINS_IMAGE_DIGEST_PATH"
fi
exit "$rc"
