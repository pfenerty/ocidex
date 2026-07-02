#!/bin/sh
# Package and push the ocidex Helm charts for a tagged release, pinning each image
# to its immutable digest. Single step under `set -e` so a failed digest resolve
# aborts BEFORE any chart is pushed — never publish a partially-pinned chart.
# (tektonic wraps this with onError:continue + exit-code capture, so the step must
# just exit non-zero on failure; the report-status step surfaces it.)
#
# crane (fetched below) resolves the multi-arch index digest of each pushed image;
# it authenticates via $DOCKER_CONFIG/config.json (the mounted registry creds).
# `${VAR#prefix}` is avoided (tektonic synth can drop it); use sed instead.
set -e

TAG="$(params.source-branch)"
TAG=$(echo "$TAG" | sed 's|^refs/tags/||')
VERSION=$(echo "$TAG" | sed 's|^v||')

# --- Fetch crane (alpine/helm image has no digest tool) ----------------------
CRANE_VERSION="v0.20.2"
case "$(uname -m)" in
  x86_64) CRANE_ARCH="x86_64" ;;
  aarch64 | arm64) CRANE_ARCH="arm64" ;;
  *) echo "ERROR: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac
wget -qO /tmp/crane.tgz \
  "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz"
tar -xzf /tmp/crane.tgz -C /tmp crane

# --- Resolve digests and bake them into chart values -------------------------
# App components (charts/ocidex); operator is a separate chart handled below.
COMPONENTS="api scanner-worker enrichment-worker oci-metadata-worker user-enricher-worker provenance-worker web"

# Build the image.digests block in a file (portable: no embedded newlines in awk vars).
echo "  digests:" > /tmp/digests-block.yaml
for comp in $COMPONENTS; do
  ref="ghcr.io/pfenerty/ocidex-${comp}:${TAG}"
  digest=$(/tmp/crane digest "$ref")
  if [ -z "$digest" ]; then
    echo "ERROR: could not resolve digest for $ref" >&2
    exit 1
  fi
  echo "resolved $ref -> $digest"
  echo "    ${comp}: ${digest}" >> /tmp/digests-block.yaml
done

# Replace the "  digests: {}" placeholder line with the resolved block.
awk '/^  digests: \{\}$/ {
       while ((getline line < "/tmp/digests-block.yaml") > 0) print line
       close("/tmp/digests-block.yaml"); next
     }
     { print }' charts/ocidex/values.yaml > /tmp/ocidex-values.yaml
mv /tmp/ocidex-values.yaml charts/ocidex/values.yaml

# Operator chart: single image, scalar image.digest.
op_ref="ghcr.io/pfenerty/ocidex-operator:${TAG}"
op_digest=$(/tmp/crane digest "$op_ref")
if [ -z "$op_digest" ]; then
  echo "ERROR: could not resolve digest for $op_ref" >&2
  exit 1
fi
echo "resolved $op_ref -> $op_digest"
sed -i "s|^  digest: \"\"\$|  digest: ${op_digest}|" charts/ocidex-operator/values.yaml

echo "--- charts/ocidex/values.yaml image block ---"
grep -A 12 '^image:' charts/ocidex/values.yaml

# --- Package and push --------------------------------------------------------
helm package charts/ocidex --version "${VERSION}" --app-version "${TAG}"
helm package charts/ocidex-operator --version "${VERSION}" --app-version "${TAG}"
helm push "ocidex-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
helm push "ocidex-operator-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
