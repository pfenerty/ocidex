---
title: Enrichment
description: How OCIDex adds what an SBOM doesn't say.
sidebar:
  order: 3
---

An SBOM lists what's inside an artifact. It rarely says where the artifact came from, who built
it, or whether it's signed. **Enrichment** fills that in after the SBOM is stored.

Each enricher runs in its own worker. When an SBOM is ingested, OCIDex queues one job per
enricher. Ingest doesn't wait for them, so a new SBOM shows up at once and its enrichment fills in
over the next seconds or minutes.

| Enricher | Adds |
| --- | --- |
| **OCI metadata** | Image labels, architecture, OS, build time and source URL, read from the registry. |
| **Git** | The source commit, from GitHub, using the revision and repository the image labels name. |
| **User** | Metadata supplied with an upload, like version and build date. |
| **Provenance** | Signatures and attestations, checked against the registry's [trust policy](/concepts/sources-and-registries/#trust-policy). |

Enrichment is retried when it fails, and a job that runs out of attempts stays visible on the
**Jobs** page with a retry button.

## Labels matter

The OCI metadata and git enrichers work from the image's standard labels. An image built with
`org.opencontainers.image.source`, `org.opencontainers.image.revision`,
`org.opencontainers.image.version` and `org.opencontainers.image.created` gets a linked source
repository, commit, version and build date. An image without them gets less.

## Vulnerabilities are separate

Vulnerability matching is not an enricher. It runs against packages rather than SBOMs, so a new
advisory reaches every affected SBOM without enriching anything again. See
[Vulnerabilities](/concepts/vulnerabilities/).
