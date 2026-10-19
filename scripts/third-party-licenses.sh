#!/bin/sh
# Collect the license texts of every third-party Go module linked into the given packages,
# for shipping in the container images at /licenses (ocidex-9rqq). Apache-2.0, MIT and BSD
# require the license text to travel with distributed binaries.
#
# Usage: scripts/third-party-licenses.sh <outdir> <package>...
# Run from the repo root with the same GOOS/GOARCH/CGO_ENABLED as the build, so `go list`
# sees the dependency graph that is actually linked.
#
# Layout of <outdir>:
#   LICENSE                      OCIDex's own license
#   go/                          the Go standard library and runtime, and what it vendors
#   <module>@<version>/<file>    each license, copying, notice file at the module root
#   README                       what this is, and where to get each module's source
#
# MPL-2.0 requires the source of covered files to be available, not shipped: README lists
# the MPL modules with their Go module proxy source URLs, rather than copying ~13MB of source.
# A linked module with no license file at its root fails the build, so a new dependency
# can't slip in unlicensed.
set -eu

out="${1:?usage: third-party-licenses.sh <outdir> <package>...}"
shift
[ "$#" -gt 0 ] || { echo "third-party-licenses: no packages given" >&2; exit 1; }

mkdir -p "$out/go"
cp LICENSE "$out/LICENSE"

# The Go standard library and runtime. Wolfi's go package drops $GOROOT/LICENSE and PATENTS,
# so fall back to the copies in scripts/licenses/go. The packages the standard library
# vendors (golang.org/x/crypto and friends) are linked too, with their own license files.
goroot=$(go env GOROOT)
for f in LICENSE PATENTS; do
  if [ -f "$goroot/$f" ]; then cp "$goroot/$f" "$out/go/$f"; else cp "scripts/licenses/go/$f" "$out/go/$f"; fi
done
for dir in "$goroot"/src/vendor/*/*/*/; do
  [ -d "$dir" ] || continue
  mod=${dir#"$goroot/src/vendor/"}
  mkdir -p "$out/go/vendor/$mod"
  cp "$dir"LICENSE* "$dir"PATENTS* "$out/go/vendor/$mod" 2>/dev/null || true
done

# Not piped straight into sort: a pipeline would hide a go list failure and ship an empty bundle.
mods=$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{with .Replace}}{{.Dir}}{{else}}{{.Dir}}{{end}}{{end}}{{end}}' "$@")
mods=$(echo "$mods" | sort -u)
[ -n "$mods" ] || { echo "third-party-licenses: go list found no modules" >&2; exit 1; }

missing=$(mktemp)
trap 'rm -f "$missing"' EXIT
echo "$mods" | while read -r path version dir; do
  [ -n "$path" ] || continue
  dest="$out/$path@$version"
  found=0
  for f in $(ls "$dir" | grep -i -E '^(licen[cs]e|copying|notice|unlicense)' | grep -v -E '\.go$'); do
    [ -f "$dir/$f" ] || continue
    mkdir -p "$dest"
    cp "$dir/$f" "$dest/$f"
    found=1
  done
  if [ "$found" = 0 ]; then
    echo "third-party-licenses: no license file at the root of $path@$version ($dir)" >&2
    echo "$path@$version" >> "$missing"
  fi
done

[ ! -s "$missing" ] || exit 1

# Go module proxy paths escape each upper-case letter as '!' plus its lower case.
proxy_url() {
  printf 'https://proxy.golang.org/%s/@v/%s.zip' \
    "$(echo "$1" | sed 's/[A-Z]/!&/g' | tr '[:upper:]' '[:lower:]')" "$2"
}

{
  echo "Third-party licenses for the OCIDex binaries in this image."
  echo
  echo "Each directory is a Go module linked into an OCIDex binary, named <module>@<version>,"
  echo "holding the license files from that module's source. go/ is the Go standard library,"
  echo "and go/vendor/ the packages it vendors."
  echo "The source of every module is available from the Go module proxy at"
  echo "https://proxy.golang.org/<module>/@v/<version>.zip."
  echo
  echo "These modules are licensed (in whole or part) under the Mozilla Public License 2.0."
  echo "Their source code form is available at:"
  echo
  echo "$mods" | while read -r path version dir; do
    [ -n "$path" ] || continue
    if grep -l -q 'Mozilla Public License' "$out/$path@$version"/* 2>/dev/null; then
      echo "  $path@$version  $(proxy_url "$path" "$version")"
    fi
  done
} > "$out/README"
