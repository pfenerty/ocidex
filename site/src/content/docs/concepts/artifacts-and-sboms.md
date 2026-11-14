---
title: Artifacts, SBOMs and components
description: What OCIDex stores, and the words the UI uses for it.
sidebar:
  order: 1
---

## Artifact

An **artifact** is a thing you ship: a container image, an application, a library. It has a name
and a type, and for a container image the name is the repository, like `ghcr.io/acme/api`.

An artifact collects SBOMs over time. Each new build or tag adds one, so the artifact's history is
its list of SBOMs.

## SBOM

An **SBOM** is one CycloneDX document describing one artifact at one point in time. OCIDex keeps
the document exactly as it arrived, and also breaks it down into components, dependency edges and
licenses so they can be searched.

For a container image an SBOM is identified by its image digest. It also carries:

- a **version**: the tag or release it describes, like `1.4.2`;
- an **architecture**: `amd64`, `arm64` and so on. A multi-arch image gets one SBOM per
  architecture;
- a **flavor**: the base distribution, like `alpine`, `debian` or `wolfi`. OCIDex detects it from
  the SBOM itself. It keeps the changelog of `myapp:1.2-alpine` apart from that of
  `myapp:1.2-debian`, so the two lines don't look like they swap every package on every release.

OCIDex accepts CycloneDX JSON. SBOMs from syft (which OCIDex itself uses), apko and Trivy work
well. See [what makes a good SBOM](#what-makes-a-good-sbom) below.

## Package, package version and component

The UI uses three words for the things inside an SBOM, and each one counts something different.

| Word | What it counts | Example |
| --- | --- | --- |
| **Package** | One library, at any version | `openssl` |
| **Package version** | One package at one version | `openssl 3.3.2` |
| **Component** | One entry in one SBOM | `openssl 3.3.2` in ten SBOMs is ten components |

Syft also records files, applications and the operating system as components. They are components,
but not packages, so package counts leave them out.

Components are never merged across SBOMs. Each SBOM keeps exactly what it said, and search
deduplicates at query time.

## Licenses

Each component's licenses are stored by SPDX id and grouped into **permissive**, **weak copyleft**
and **copyleft**. The licenses page lists every license across the SBOMs you can see, and each
artifact has a license summary of its latest SBOM.

## What makes a good SBOM

OCIDex works with any valid CycloneDX JSON, but some fields make the difference between a precise
diff and a noisy one:

- **Package URLs (purls) on every component.** They are how OCIDex knows two components are the
  same package. Without them it falls back to matching by name.
- **`distro` qualifiers on OS package purls**, like `pkg:apk/wolfi/curl?distro=wolfi-os`. They keep
  Alpine and Wolfi packages from matching each other.
- **A dependency graph** (`dependencies`, rooted at `metadata.component`). It is what the diff's tree
  view draws.
- **OS metadata properties**, like `syft:image:os:name`, for flavor detection.

A recent syft gives you all four by default.
