---
title: Sources and registries
description: The ways an SBOM gets into OCIDex.
sidebar:
  order: 2
---

Every SBOM comes in through a **source**. A source belongs to a [namespace](/concepts/namespaces-and-access/),
and the namespace decides who can see what came through it.

There are three kinds:

- **A registry** is a container registry OCIDex scans itself. OCIDex pulls each selected image,
  generates its SBOM with syft, and ingests it.
- **An upload source** is a channel for SBOMs you generate elsewhere: in CI, with `ocidex-cli`, or
  with a plain `POST` to the API.
- **A cluster** is a Kubernetes cluster whose agent reports what it runs. OCIDex can scan those
  images for you. See [Clusters and coverage](/concepts/clusters-and-coverage/).

Use a registry when you want OCIDex to keep up with what's published. Use uploads when the SBOM
is best made at build time, or the artifact isn't a container image at all, such as a Go binary or
an npm package.

## Registry scans

A registry has a URL, optional credentials, and rules for what to scan:

- **Repositories**: an explicit list, or patterns to match against the registry's catalog.
- **Tags**: patterns, then a **window** of the newest tags per repository (50 by default). Newest
  is decided by semver, by image creation time, or alphabetically, and you can also drop tags
  older than a cutoff.

The window keeps a busy repository from growing without bound. The registry form previews which
tags a setting would select before you save it.

Scans run on a schedule, when the registry calls OCIDex's webhook after a push, or on demand. Each
image is scanned once per digest: a tag that moves to a new digest gets a new SBOM, and a tag that
didn't move costs nothing.

A multi-arch image is scanned once per platform, and each platform gets its own SBOM.

## Trust policy

A registry can also carry a **trust policy**: a public key, or a keyless signing identity and
issuer. The provenance enricher then verifies each image's signatures and attestations against it,
and the UI shows whether the image is verified.

## Retention

By default OCIDex deletes nothing. When an operator turns retention on, registry SBOMs that fall
out of their scan window are deleted, and other artifacts keep their newest versions. Images that
are still running in a registered cluster are always kept.
