---
title: Push SBOMs from CI
description: Send SBOMs to OCIDex from GitHub Actions, GitLab CI and Tekton.
sidebar:
  order: 3
---

There are two ways to get your builds into OCIDex. Pick by what you build.

- **Container images you push to a registry:** let OCIDex scan the registry itself. Add the
  registry under **Sources** (**Admin → Sources** for an admin), with webhook or poll mode, and every pushed image gets an SBOM with no
  CI changes. See [Sources and registries](/concepts/sources-and-registries/).
- **Anything else, or SBOMs you want made at build time:** generate the SBOM in CI and push it.
  That's what this page covers.

## Before you start

1. **An upload source**, which decides the namespace your SBOMs land in:
   `ocidex-cli source create --name ci --namespace acme`.
2. **A key that can only ingest:** `ocidex-cli key create --name ci --capability ingest`. Its owner
   needs a role that may ingest in that namespace (owner, maintainer or developer).
3. Store the key in your CI system's secrets as `OCIDEX_API_KEY`, and the server URL as
   `OCIDEX_URL`.

## What to send

**For a binary or package**, tell OCIDex what the SBOM describes, because a scan of a source
directory describes the directory, not what you built. `ocidex-cli sbom push` takes the subject's
type, name and version, and hashes the artifact file for its digest.

**For a container image**, scan the pushed image by digest, so the SBOM names exactly what's in the
registry. OCIDex also needs the image's version, architecture and build date. It reads them from
the image's `org.opencontainers.image.version` and `org.opencontainers.image.created` labels when
they're set; pass the rest with `--version`, `--arch` and `--build-date`.

## GitHub Actions

```yaml title=".github/workflows/sbom.yml"
name: sbom
on:
  push:
    tags: ["v*"]

jobs:
  binary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: stable }
      - run: go build -o bin/myapp ./cmd/myapp
      - uses: anchore/sbom-action@v0
        with:
          file: bin/myapp
          format: cyclonedx-json
          output-file: myapp.cdx.json
      - run: go install github.com/pfenerty/ocidex/cmd/ocidex-cli@latest
      - run: |
          ocidex-cli sbom push myapp.cdx.json --source acme/ci \
            --artifact-file bin/myapp \
            --subject-type application --subject-name myapp \
            --subject-purl "pkg:golang/github.com/acme/myapp@${GITHUB_REF_NAME}" \
            --version "${GITHUB_REF_NAME}" --arch amd64
        env:
          OCIDEX_URL: ${{ vars.OCIDEX_URL }}
          OCIDEX_API_KEY: ${{ secrets.OCIDEX_API_KEY }}

  image:
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/acme/myapp:${{ github.ref_name }}
      - uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/acme/myapp@${{ steps.build.outputs.digest }}
          format: cyclonedx-json
          output-file: image.cdx.json
      - run: go install github.com/pfenerty/ocidex/cmd/ocidex-cli@latest
      - run: |
          ocidex-cli sbom push image.cdx.json --source acme/ci \
            --version "${GITHUB_REF_NAME}" --arch amd64 \
            --build-date "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        env:
          OCIDEX_URL: ${{ vars.OCIDEX_URL }}
          OCIDEX_API_KEY: ${{ secrets.OCIDEX_API_KEY }}
```

## GitLab CI

```yaml title=".gitlab-ci.yml"
sbom:
  stage: deploy
  image: golang:1
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - go build -o bin/myapp ./cmd/myapp
    - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    - syft file:bin/myapp -o cyclonedx-json > myapp.cdx.json
    - go install github.com/pfenerty/ocidex/cmd/ocidex-cli@latest
    - >
      ocidex-cli sbom push myapp.cdx.json --source acme/ci
      --artifact-file bin/myapp
      --subject-type application --subject-name myapp
      --version "$CI_COMMIT_TAG" --arch amd64
  # OCIDEX_URL and OCIDEX_API_KEY come from the project's CI/CD variables (masked).
```

## Tekton

```yaml
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: ocidex-push-sbom
spec:
  params:
    - name: sbom
    - name: artifact
    - name: name
    - name: version
  workspaces:
    - name: source
  steps:
    - name: push
      image: ghcr.io/pfenerty/ocidex-cli:<version>
      workingDir: $(workspaces.source.path)
      env:
        - name: OCIDEX_URL
          value: https://ocidex.example.com
        - name: OCIDEX_API_KEY
          valueFrom:
            secretKeyRef: { name: ocidex-ci, key: api-key }
      args:
        - sbom
        - push
        - $(params.sbom)
        - --source=acme/ci
        - --artifact-file=$(params.artifact)
        - --subject-type=application
        - --subject-name=$(params.name)
        - --version=$(params.version)
        - --arch=amd64
```

## Checking it worked

`ocidex-cli sbom push` prints the new SBOM's id and its component count. Open the artifact in
OCIDex, or ask the CLI:

```sh
ocidex-cli artifact list -o json | jq '.[] | select(.name=="myapp")'
```

If the push is refused:

| Answer | Cause |
| --- | --- |
| `401` | No key, or a key that's been deleted. |
| `403` | The key lacks `ingest`, or its owner's role in the source's namespace doesn't allow it. |
| `422` and `missing required metadata` | A container SBOM without a version, architecture or build date. Pass them as parameters. |
| `429` | The per-key rate limit. Wait for `Retry-After`, then retry. |
