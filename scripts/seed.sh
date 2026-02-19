#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8080/api/v1}"

# --- Dependency checks ---

for cmd in oras syft curl; do
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
#
# For pinned images (tag_pattern is empty), tags are listed literally in count
# field and tag discovery is skipped.

IMAGE_SETS=(
  # All images below populate org.opencontainers.image.* in config labels
  # (not just index/manifest annotations), which is what the OCI enricher reads.

  # --- Base images (rich OCI config labels) ---

  # Red Hat UBI 9 Minimal — rpm ecosystem, exemplary OCI label compliance
  # Labels: .created, .description, .licenses, .revision, .source, .title, .url, .version
  "registry.access.redhat.com/ubi9/ubi-minimal|^9\\.[0-9]+-[0-9]+$|5|Red Hat UBI 9 Minimal"

  # --- Bitnami images (Debian-based, 8+ OCI labels each) ---
  # Labels: .base.name, .created, .description, .licenses, .ref.name, .title, .vendor, .version

  # Bitnami PostgreSQL — relational database
  "docker.io/bitnami/postgresql|^(16|17)\\.[0-9]+-debian-12-r[0-9]+$|4|Bitnami PostgreSQL"

  # Bitnami Redis — in-memory data store
  "docker.io/bitnami/redis|^7\\.[24]\\.[0-9]+-debian-12-r[0-9]+$|4|Bitnami Redis"

  # Bitnami Nginx — web server / reverse proxy
  "docker.io/bitnami/nginx|^1\\.(2[6-7])\\.[0-9]+-debian-12-r[0-9]+$|4|Bitnami Nginx"

  # Bitnami Kafka — event streaming platform
  "docker.io/bitnami/kafka|^3\\.[89]\\.[0-9]+-debian-12-r[0-9]+$|4|Bitnami Kafka"

  # Bitnami Elasticsearch — search engine
  "docker.io/bitnami/elasticsearch|^8\\.(1[5-7])\\.[0-9]+-debian-12-r[0-9]+$|4|Bitnami Elasticsearch"

  # --- Application images (use docker/metadata-action or equivalent) ---
  # These populate OCI labels via CI, typically: .title, .description, .source, .version, .created, .revision

  # Harbor Core — cloud-native registry (Go app on Photon OS)
  "docker.io/goharbor/harbor-core|^v2\\.[1-9][0-9]*\\.[0-9]+$|4|Harbor Core"

  # Keycloak — identity and access management (Java/Quarkus on UBI)
  "docker.io/keycloak/keycloak|^2[5-6]\\.[0-9]+\\.[0-9]+$|4|Keycloak"

  # Gitea — lightweight Git forge (Go app)
  "docker.io/gitea/gitea|^1\\.2[2-3]\\.[0-9]+$|4|Gitea"

  # Traefik — cloud-native reverse proxy / ingress (Go binary on Alpine)
  "docker.io/library/traefik|^v3\\.[12]\\.[0-9]+$|4|Traefik"

  # Minio — S3-compatible object storage (Go binary)
  "docker.io/minio/minio|^RELEASE\\.2024-(1[0-2]|0[7-9])-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$|4|MinIO"
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

# --- Generate and ingest SBOMs ---

SUCCESS=0
FAIL=0
SKIP=0

for i in "${!ALL_IMAGES[@]}"; do
  image="${ALL_IMAGES[$i]}"
  idx=$((i + 1))

  echo "[${idx}/${TOTAL}] Generating SBOM for ${image}..."

  # Resolve the tag to a platform-specific image manifest digest (not the
  # manifest list / image index). The ingest API rejects index digests.
  tag="${image##*:}"
  repo="${image%:*}"
  digest=$(oras resolve --platform linux/amd64 "${image}" 2>/dev/null || true)

  if [ -z "$digest" ]; then
    echo "  -> SKIP: could not resolve digest for ${image}"
    SKIP=$((SKIP + 1))
    continue
  fi

  echo "  -> Resolved ${tag} -> ${digest}"

  # Generate CycloneDX SBOM directly from the registry (no docker pull needed).
  sbom_json=$(syft "registry:${repo}@${digest}" -o cyclonedx-json 2>/dev/null || true)

  if [ -z "$sbom_json" ]; then
    echo "  -> SKIP: syft produced empty output for ${image}"
    SKIP=$((SKIP + 1))
    continue
  fi

  # Count components for display.
  comp_count=$(echo "$sbom_json" | grep -o '"bom-ref"' | wc -l | tr -d ' ')

  echo "  -> SBOM generated (${comp_count} components), submitting to ${BASE_URL}/sbom..."

  response=$(echo "$sbom_json" | curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/sbom" \
    -H "Content-Type: application/json" \
    -d @-)

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 201 ]; then
    echo "  -> ${http_code} OK: ${body}"
    SUCCESS=$((SUCCESS + 1))
  else
    echo "  -> ${http_code} ERROR: ${body}"
    FAIL=$((FAIL + 1))
  fi

  # Small delay between requests to be kind to registries and the API.
  sleep 0.5
done

echo ""
echo "==========================================="
echo "Seed complete."
echo "  Succeeded: ${SUCCESS}"
echo "  Failed:    ${FAIL}"
echo "  Skipped:   ${SKIP}"
echo "  Total:     ${TOTAL}"
echo "==========================================="
echo ""
echo "Verify: curl -s ${BASE_URL}/artifacts | jq '.data[] | {name, type, sbomCount}'"
