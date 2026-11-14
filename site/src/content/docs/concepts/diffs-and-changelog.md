---
title: Diffs and the changelog
description: How OCIDex compares two SBOMs, and decides that two components are the same package.
sidebar:
  order: 5
---

Every artifact has a **changelog**: each SBOM compared with the one before it, newest first. A
**diff** compares any two SBOMs you pick.

Both report each package as **added**, **removed**, **upgraded**, **downgraded** or **modified**
(the version changed, but its direction can't be told).

## Tree and flat views

When the SBOM has a dependency graph, the diff opens as a **tree**: the image's direct dependencies
at the top, and chips on each row counting the changes underneath it. A change deep in the graph
shows up under the dependency that brought it in. The **flat** view lists every changed package,
and is the fallback when there is no graph.

## When are two components the same package?

A diff has to decide whether `curl 8.6` before and `curl 8.7` after are one package that was
upgraded, or one that was removed and another that was added. OCIDex decides with these rules,
in order:

1. **The purl, minus its version.** Qualifiers that say where a package comes from (`distro`,
   `arch`, `epoch`, `repository_url`) stay part of its identity; noise like `download_url` and
   checksums is dropped. So a Wolfi `curl` never matches an Alpine `curl`, and a mirror change is
   not a change.
2. **Type, group and name**, for a component without a purl. This is coarser: two distributions'
   packages with the same name can match.
3. **Versioned names.** A removed `python-3.11` and an added `python-3.12` are folded into one
   upgrade, unless both versions are installed on one side.

## Flavors and architectures

A changelog only compares like with like. SBOMs are grouped by **architecture** and
[**flavor**](/concepts/artifacts-and-sboms/#sbom), so the `arm64` Alpine line of an image has its own
timeline, separate from the `amd64` Debian one.
