#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8080/api/v1}"
ZOT_ADDR="${2:-localhost:5000}"

# --- Dependency checks ---

for cmd in oras syft curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not found in PATH." >&2
    echo "       Run 'flox activate' to enter the dev environment." >&2
    exit 1
  fi
done

# --- Docker credential workaround ---
# ORAS and syft try to use docker-credential-osxkeychain which may not be
# available inside the flox environment. Create a minimal Docker config
# with no credential helpers so anonymous registry access works.

DOCKER_CONFIG_DIR="$(mktemp -d)"
echo '{}' > "${DOCKER_CONFIG_DIR}/config.json"
export DOCKER_CONFIG="${DOCKER_CONFIG_DIR}"

cleanup() {
  rm -rf "${DOCKER_CONFIG_DIR}"
}
trap cleanup EXIT

# --- Image definitions ---
# Each entry: "registry/repo|tag_pattern|count|description"
#
# For ORAS-discovered images, tag_pattern is a grep -E regex applied to the
# tag list, and count is how many matching tags to take (newest last).

IMAGE_SETS=(
  # Red Hat UBI 10 — rpm ecosystem, OCI-spec manifests
  # "registry.access.redhat.com/ubi10|^10\\.[0-9]|3|Red Hat UBI 10"

  # Ubuntu 24.x — Debian ecosystem
  "quay.io/lib/ubuntu|^22\\.[0-9]+$|3|Ubuntu 24"

  # Alpine 3.x — minimal musl-based image
  "quay.io/lib/alpine|^3\\.[0-9]+$|3|Alpine 3"

  # Traefik v3.6.x — cloud-native reverse proxy (Go binary on Alpine)
  "quay.io/lib/traefik|^v3\\.5\\.[0-9]+$|3|Traefik v3.6"

  # Keycloak 26.x — identity and access management (Quarkus on UBI)
  "quay.io/keycloak/keycloak|^26\\.[0-9]+\\.[0-9]+$|3|Keycloak 26"

  # Ceph v19.x — distributed storage
  "quay.io/ceph/ceph|^v19\\.[0-9]+\\.[0-9]+$|3|Ceph v19"

  # Amazon Linux 2023.7.x
  "quay.io/lib/amazonlinux|^2023\\.7\\.|3|Amazon Linux 2023.7"
)

# --- Discover and collect all images ---

declare -a ALL_IMAGES=()

for entry in "${IMAGE_SETS[@]}"; do
  IFS='|' read -r repo pattern count desc <<< "$entry"

  echo "=== ${desc} ==="
  echo "    Repo: ${repo}"
  echo "    Discovering tags (pattern: ${pattern}, max: ${count})..."

  all_tags=$(oras repo tags "${repo}" 2>/dev/null || true)

  if [ -z "$all_tags" ]; then
    echo "    WARN: Could not list tags for ${repo}, skipping."
    echo ""
    continue
  fi

  matched_tags=()
  while IFS= read -r tag; do
    matched_tags+=("$tag")
  done < <(echo "$all_tags" | grep -E "$pattern" | tail -n "$count")

  if [ "${#matched_tags[@]}" -eq 0 ]; then
    echo "    WARN: No tags matched pattern '${pattern}', skipping."
    echo ""
    continue
  fi

  echo "    Found ${#matched_tags[@]} tags:"
  for tag in "${matched_tags[@]}"; do
    echo "      - ${tag}"
    ALL_IMAGES+=("${repo}:${tag}")
  done
  echo ""
done

TOTAL="${#ALL_IMAGES[@]}"
if [ "$TOTAL" -eq 0 ]; then
  echo "ERROR: No images discovered. Check network connectivity and registry access." >&2
  exit 1
fi

echo "==========================================="
echo "Total images to process: ${TOTAL}"
echo "==========================================="
echo ""

# --- Helpers ---

# Strip the registry hostname from a repo path, leaving only the path component.
# e.g. docker.io/bitnami/postgresql -> bitnami/postgresql
#      registry.access.redhat.com/ubi9/ubi-minimal -> ubi9/ubi-minimal
local_repo() {
  local repo="$1"
  local first="${repo%%/*}"
  if [[ "$first" == *.* ]]; then
    echo "${repo#*/}"
  else
    echo "$repo"
  fi
}

# --- Copy indexes to Zot, generate and ingest SBOMs ---

SUCCESS=0
FAIL=0
SKIP=0

for i in "${!ALL_IMAGES[@]}"; do
  image="${ALL_IMAGES[$i]}"
  idx=$((i + 1))
  tag="${image##*:}"
  repo="${image%:*}"
  dest_repo="$(local_repo "${repo}")"
  dest="${ZOT_ADDR}/${dest_repo}:${tag}"

  echo "[${idx}/${TOTAL}] ${image}"

  # Guard: skip images that use Docker manifest format (not OCI spec).
  src_manifest=$(oras manifest fetch "${image}" 2>/dev/null || true)
  src_media_type=$(echo "$src_manifest" | jq -r '.mediaType // empty' 2>/dev/null || true)
  if [[ "$src_media_type" == *"vnd.docker"* ]]; then
    echo "  -> SKIP: Docker manifest format (mediaType: ${src_media_type})"
    SKIP=$((SKIP + 1))
    continue
  fi

  echo "  -> Copying index to zot: ${dest}..."

  if ! oras copy --to-plain-http "${image}" "${dest}" 2>/dev/null; then
    echo "  -> SKIP: oras copy failed"
    SKIP=$((SKIP + 1))
    continue
  fi

  # Fetch the manifest to discover available linux platforms.
  manifest=$(oras manifest fetch --plain-http "${dest}" 2>/dev/null || true)
  if [ -z "$manifest" ]; then
    echo "  -> SKIP: could not fetch manifest from zot"
    SKIP=$((SKIP + 1))
    continue
  fi

  # For an image index, extract linux architectures.
  # For a single-arch manifest, fall back to resolving the tag directly.
  arches=$(echo "$manifest" | jq -r '
    if .manifests then
      .manifests[] | select(.platform.os == "linux") | .platform.architecture
    else
      "single"
    end
  ' 2>/dev/null || true)

  if [ -z "$arches" ]; then
    echo "  -> SKIP: could not determine platforms"
    SKIP=$((SKIP + 1))
    continue
  fi

  while IFS= read -r arch; do
    if [ "$arch" = "single" ]; then
      platform_label="(single-arch)"
      digest=$(oras resolve --plain-http "${dest}" 2>/dev/null || true)
    else
      platform_label="linux/${arch}"
      digest=$(oras resolve --plain-http --platform "linux/${arch}" "${dest}" 2>/dev/null || true)
    fi

    if [ -z "$digest" ]; then
      echo "  -> SKIP [${platform_label}]: could not resolve digest"
      SKIP=$((SKIP + 1))
      continue
    fi

    echo "  -> [${platform_label}] ${digest} — generating SBOM..."

    sbom_json=$(SYFT_REGISTRY_INSECURE_USE_HTTP=true \
      syft "registry:${ZOT_ADDR}/${dest_repo}@${digest}" -o cyclonedx-json 2>/dev/null || true)

    if [ -z "$sbom_json" ]; then
      echo "  -> SKIP [${platform_label}]: syft produced empty output"
      SKIP=$((SKIP + 1))
      continue
    fi

    comp_count=$(echo "$sbom_json" | grep -o '"bom-ref"' | wc -l | tr -d ' ')
    echo "  -> [${platform_label}] ${comp_count} components, submitting..."

    response=$(echo "$sbom_json" | curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/sbom" \
      -H "Content-Type: application/json" \
      -d @-)

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" -eq 201 ]; then
      echo "  -> [${platform_label}] ${http_code} OK: ${body}"
      SUCCESS=$((SUCCESS + 1))
    else
      echo "  -> [${platform_label}] ${http_code} ERROR: ${body}"
      FAIL=$((FAIL + 1))
    fi

    sleep 0.5
  done <<< "$arches"

  echo ""
done

echo "==========================================="
echo "Seed complete."
echo "  Succeeded: ${SUCCESS}"
echo "  Failed:    ${FAIL}"
echo "  Skipped:   ${SKIP}"
echo "==========================================="
echo ""
echo "Verify: curl -s ${BASE_URL}/artifacts | jq '.data[] | {name, type, sbomCount}'"
