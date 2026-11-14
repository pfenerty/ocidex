---
title: Label your images
description: The image labels OCIDex reads, which ones it requires, and how to set them.
sidebar:
  order: 2
---

OCIDex reads standard OCI labels and annotations from your images to name versions, link source
code and show what each image is. Two of them are **required** to ingest a container image's SBOM.

## The minimum

A container image's SBOM needs a version, an architecture and a build date, or it's rejected with
`422`. The architecture is set automatically by every common build tool. Set the other two as
labels:

```dockerfile
ARG VERSION=dev
ARG BUILDTIME
LABEL org.opencontainers.image.version="$VERSION"
LABEL org.opencontainers.image.created="$BUILDTIME"
```

```sh
docker build \
  --build-arg VERSION=v1.4.2 \
  --build-arg BUILDTIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t registry.example.com/my-service:v1.4.2 .
```

If you upload SBOMs yourself, you can pass `version`, `architecture` and `buildDate` with the
upload instead. Images OCIDex finds running in a cluster fall back to their tag, then their short
digest, for a version.

## Recommended labels

These fill in the rest of what OCIDex shows:

```dockerfile
LABEL org.opencontainers.image.title="my-service"
LABEL org.opencontainers.image.description="What this image does"
LABEL org.opencontainers.image.source="https://github.com/acme/my-service"
LABEL org.opencontainers.image.revision="$GIT_SHA"
LABEL org.opencontainers.image.vendor="Acme"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.url="https://acme.example.com/my-service"
LABEL org.opencontainers.image.documentation="https://acme.example.com/my-service/docs"
LABEL org.opencontainers.image.authors="team@acme.example.com"
LABEL org.opencontainers.image.base.name="debian:bookworm-slim"
```

`source` and `revision` together let the git enricher link the exact commit an image was built
from.

## Labels, manifest annotations and index annotations

The same keys can be set in three places, and OCIDex reads them at two moments:

- **At ingest**, from the SBOM. syft copies the image's **config labels** (Dockerfile `LABEL`s)
  into it. That's why the required fields have to be labels: nothing else is read in time.
- **After ingest**, the metadata enricher reads the registry directly: **manifest annotations**
  first, then config labels, then the **index annotations** of a multi-arch image. The first
  non-empty value wins.

So annotations are useful for adding metadata to an image you can't rebuild, or to a whole
multi-arch index at once, but they can't rescue an ingest that was rejected.

```sh
# Manifest annotations
docker buildx build --annotation "org.opencontainers.image.source=https://github.com/acme/my-service" ...

# Index annotations, on a multi-arch image
docker buildx build --platform linux/amd64,linux/arm64 \
  --annotation "index:org.opencontainers.image.description=My service" ...
```

For index annotations, OCIDex finds the index by looking up the image's version as a tag, so the
version tag must point at the index.

## Reference

| Key | Shown as | Older equivalents also read |
| --- | --- | --- |
| `org.opencontainers.image.version` | Version (**required**) | `org.label-schema.version`, `version` |
| `org.opencontainers.image.created` | Build date (**required**) | `org.label-schema.build-date`, `build-date` |
| `org.opencontainers.image.title` | Title | `org.label-schema.name`, `name` |
| `org.opencontainers.image.description` | Description | `org.label-schema.description`, `description` |
| `org.opencontainers.image.source` | Source repository | `org.label-schema.vcs-url`, `vcs-url` |
| `org.opencontainers.image.revision` | Commit | `org.label-schema.vcs-ref`, `vcs-ref` |
| `org.opencontainers.image.vendor` | Vendor | `org.label-schema.vendor`, `vendor` |
| `org.opencontainers.image.url` | Homepage | `org.label-schema.url`, `url` |
| `org.opencontainers.image.documentation` | Documentation | `org.label-schema.usage`, `usage` |
| `org.opencontainers.image.licenses` | Licenses | |
| `org.opencontainers.image.authors` | Authors | |
| `org.opencontainers.image.base.name`, `.base.digest` | Base image | |

The architecture and OS always come from the image's configuration, never from labels.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `422` naming `subject_version` | Add the `version` label, or pass `version` with the upload. |
| `422` naming `build_date` | Add the `created` label, or pass `buildDate`. |
| Metadata stays empty after ingest | The enricher reads the registry: check OCIDex can reach it, and has credentials for a private one. |
| Annotations don't show | They're read after ingest, by the enricher. Check they're on the manifest, not only the index, with `crane manifest <image>`. |
