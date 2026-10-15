# Releasing OCIDex

How a maintainer cuts, verifies and if necessary withdraws a release. What a release promises
is in [ADR-052](adr/0052-v1-compatibility.md). What operators do to take one is in
[UPGRADING.md](UPGRADING.md).

There are two kinds of release:

| Tag | What it releases | What it triggers |
|---|---|---|
| `vX.Y.Z[-pre]` | The server: images, Helm charts, GitHub Release | The Tekton `ocidex-tag` pipeline |
| `pkg/client/vX.Y.Z[-pre]` | The Go SDK module | Nothing. The Go proxy serves the module straight from the tag. |

Both are cut by `make release VERSION=<tag>` (`scripts/release.sh`). Pushing the tag is a
human action.

## Preconditions

- [ ] You are on `main`, in sync with `origin/main`, and the working tree is clean. The
      script refuses to run otherwise.
- [ ] The last `ocidex-push` PipelineRun on `main` is green.
- [ ] Every epic going into the release is merged, and `bd list --label v1.0 --status open`
      (or the release's label) shows nothing that should block it.
- [ ] `docs/UPGRADING.md` has a **Next release** section covering every operator-facing
      change: new required settings, renamed or removed env vars and chart values, changed
      defaults, and lossy or slow migrations.
- [ ] If the binaries use SDK API that hasn't been released yet, release the SDK first (see
      [Releasing the Go SDK](#releasing-the-go-sdk)). The server release checks this: it
      refuses to tag unless the root module builds with `GOWORK=off`.
- [ ] `git-cliff` is on PATH (it is in the Flox environment).

## Cutting a server release

1. **Pick the version.** It follows semver over the ADR-052 surface. Before 1.0, a breaking
   change bumps the minor. From 1.0 on, it bumps the major.
2. **Dry run.**

   ```bash
   flox activate -- bash -c 'DRY_RUN=1 make release VERSION=v0.1.0'
   ```

   This prints the CHANGELOG diff and the commands it would run, then restores
   CHANGELOG.md. Check that the new `## [0.1.0]` section replaced `## [unreleased]`, and
   that no older section changed. The script appends one section based on the previous
   release. If that tag is not on `main`'s history, which is true of v0.0.1-rc.1 through
   v0.0.2, it uses the commit on `main` with the same tree and says so.
3. **Rename the UPGRADING.md heading.** In `docs/UPGRADING.md`, change
   `### Next release (unreleased)` to `### 0.1.0`, add an empty **Next release** section
   above it, and commit to `main` through the normal PR flow. `release.sh` needs a clean,
   synced tree, so this lands first.
4. **Cut it.**

   ```bash
   flox activate -- make release VERSION=v0.1.0
   ```

   This writes the CHANGELOG section and commits `chore(release): v0.1.0` on `main`. It
   then creates the annotated tag `v0.1.0`.
5. **Push.** `git push origin main v0.1.0`. The tag push starts the pipeline.

## What the tag pipeline does

`ocidex-tag` (`.tektonic/pipeline.ts`) fires on `refs/tags/v*` only. Its tasks are:

- **Image builds.** It builds every image multi-arch (linux/amd64, linux/arm64) and pushes
  it to `ghcr.io/pfenerty/ocidex-<component>` tagged with the version, plus `latest` for a
  tag without a hyphen. The components are `api`, `scanner-worker`, `oci-metadata-worker`,
  `git-worker`, `user-enricher-worker`, `provenance-worker`, `vuln-worker`, `web`,
  `operator`, `k8s-agent` and `cli`. Tekton Chains signs each image and records SLSA
  provenance. BuildKit attaches provenance and an SBOM to each image.
- **`helm-check`.** It lints all three charts and checks them against the PodSecurity
  policy. It gates `helm-release`.
- **`helm-release`.** It resolves every image's index digest with `crane`, bakes the
  digests into the chart values, and packages `ocidex`, `ocidex-operator` and
  `ocidex-k8s-agent` with `--version X.Y.Z --app-version vX.Y.Z`. It pushes them to
  `oci://ghcr.io/pfenerty/charts`. Any unresolved digest aborts the job before anything is
  pushed.
- **`gh-release`.** It creates the GitHub Release. The body is the tag's
  `## [X.Y.Z]` CHANGELOG section. A tag with a hyphen is marked as a prerelease. It fails if
  the section is missing.
- **`sbom-push`.** It catalogs the shipped binaries with syft and uploads them to an OCIDex
  instance. This is report-only: it marks only its own check red and never fails the
  release.

The pipeline timeout is 4h.

## Verifying a release

Run these steps after the pipeline goes green and record the output in the release's issue.
[verifying-artifacts.md](verifying-artifacts.md) has the full background.

```bash
V=v0.1.0
curl -fsSL https://raw.githubusercontent.com/pfenerty/ocidex/main/cosign.pub -o cosign.pub

for c in api scanner-worker oci-metadata-worker git-worker user-enricher-worker \
         provenance-worker vuln-worker web operator k8s-agent cli; do
  ref="ghcr.io/pfenerty/ocidex-$c@$(crane digest ghcr.io/pfenerty/ocidex-$c:$V)"
  echo "== $ref"
  cosign verify --key cosign.pub "$ref" >/dev/null && echo "signature ok"
  cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$ref" >/dev/null \
    && echo "provenance ok"
  docker buildx imagetools inspect "$ref" --format '{{ json .SBOM }}' | jq -e . >/dev/null \
    && echo "sbom attached"
done
```

Then check each of the following:

- **Charts.** `helm pull oci://ghcr.io/pfenerty/charts/ocidex --version ${V#v}` (and the
  same for `ocidex-operator` and `ocidex-k8s-agent`). Check that `Chart.yaml` has
  `appVersion: $V` and that `values.yaml` pins every image under `image.digests`
  (or `image.digest`) to the digests above. The charts are **not signed** (ocidex-tkn9.10),
  so there is no cosign step for them yet.
- **GitHub Release.** It exists, has the right prerelease flag, and its body is the
  CHANGELOG section.
- **Version reporting.** `docker run --rm ghcr.io/pfenerty/ocidex-api:$V --version` prints
  `ocidex $V (commit …)`. A deployment of the chart answers `GET /api/v1/` with `"build": "$V"`.
- **Upgrade path.** Upgrade a deployment of the previous release (the dev cluster, or a
  throwaway one) by following UPGRADING.md. The migrate Job must succeed and the pods must
  become ready.
- **`go install`.** `go install github.com/pfenerty/ocidex/cmd/ocidex-cli@$V` succeeds. It
  ignores `go.work`, so it proves the root's SDK requirement is a published version.

File a bug for anything that fails, and link it from the release's issue.

## Rolling back a bad release

Tags, images and charts are immutable once consumers may have pulled them. Do **not** move
or re-push a release tag. Pushing a tag again re-runs the pipeline and republishes artifacts
with new digests under the same version.

- **Before anyone has deployed it:** mark the GitHub Release as a prerelease, or delete it
  (`gh release delete vX.Y.Z`), and say why in its notes. Leave the tag, the images and the
  charts in place. Fix forward with `vX.Y.Z+1`.
- **After it has been deployed:** operators go back to the previous version by following
  [UPGRADING.md § Rolling back](UPGRADING.md#rolling-back), which restores the pre-upgrade
  backup. Ship the fix as a new patch release, with an UPGRADING.md note saying who is
  affected.
- **A `latest` tag pointing at a bad release:** the next stable release moves it. If it
  cannot wait, re-tag `latest` to the previous release's digest with
  `crane tag ghcr.io/pfenerty/ocidex-<c>@<digest> latest`.

## Releasing the Go SDK

```bash
flox activate -- bash -c 'DRY_RUN=1 make release VERSION=pkg/client/v0.1.0'
flox activate -- make release VERSION=pkg/client/v0.1.0
git push origin pkg/client/v0.1.0
# point the root module at it (on a branch, via PR):
GOWORK=off go get github.com/pfenerty/ocidex/pkg/client@v0.1.0 && GOWORK=off go mod tidy
```

The script tests `pkg/client` with `GOWORK=off` before tagging. No CHANGELOG section is
written, and the tag pipeline ignores the tag. The SDK's major version tracks the API's
`/api/vN` prefix.
