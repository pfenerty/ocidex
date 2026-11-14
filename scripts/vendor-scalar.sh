#!/bin/sh
# Vendor the Scalar API reference renderer served at /api/docs (ocidex-a0p4).
#
# The bundle is embedded in the API binary instead of loaded from a CDN, so the
# reference works in air-gapped installs and the page's CSP can stay at
# script-src 'self'. The version and checksum are pinned here; bumping them is
# the whole upgrade, followed by a look at /api/docs in a browser, because
# Scalar's configuration keys (see internal/api/apiref.go) do change between
# minors.
#
# Usage: scripts/vendor-scalar.sh   (from the repo root)
set -eu

VERSION=1.76.4
SHA256=93951f1794b0463b87ab58d0557a6610075af79a9f94c2a3f261c993bc7f3913

dest=internal/api/apiref
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/standalone.js" \
	"https://unpkg.com/@scalar/api-reference@${VERSION}/dist/browser/standalone.js"
echo "${SHA256}  $tmp/standalone.js" | shasum -a 256 -c - >/dev/null

# -n drops the file name and timestamp, so re-vendoring the same version is a
# byte-identical no-op in git.
gzip -9 -n -c "$tmp/standalone.js" >"$dest/scalar.js.gz"
curl -fsSL -o "$dest/LICENSE.scalar" "https://raw.githubusercontent.com/scalar/scalar/main/LICENSE"
echo "$VERSION" >"$dest/SCALAR_VERSION"
echo "vendored @scalar/api-reference@${VERSION} into $dest"
