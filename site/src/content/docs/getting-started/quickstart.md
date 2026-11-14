---
title: Quickstart
description: Run OCIDex on your machine, scan a public image and browse its SBOM, vulnerabilities and changelog.
sidebar:
  order: 1
---

This takes you from nothing to a running OCIDex with real SBOMs in it, in about fifteen minutes,
most of which is waiting for a build. You'll scan three versions of a public image, then look at
its packages, its vulnerabilities and what changed between versions.

The demo runs on your machine only. Its sign-in accepts anyone, so don't expose it to a network.

## Before you start

You need:

- **Docker** with Compose v2 (`docker compose version` works), and about 8 GB of free disk;
- **git**, **make** and **openssl**, which most Linux and macOS machines already have.

You don't need an OAuth app, a `.env` file or a Kubernetes cluster.

## 1. Start OCIDex

```sh
git clone https://github.com/pfenerty/ocidex.git
cd ocidex
make demo
```

`make demo` builds every OCIDex image from source and starts the whole stack with Docker Compose:
PostgreSQL, NATS, the API, the scanner, the enrichers, the vulnerability worker and the web UI. The
first build takes several minutes. Later starts reuse it.

When it returns, open `http://localhost:3000` in your browser.

## 2. Sign in

Choose the **Continue with …** button. The demo's sign-in is a mock identity provider that lets
you pick who you are.
Pick **demo-admin**, the installation admin. (**demo-viewer** is an ordinary user, for when you
want to see what someone without admin rights sees.)

## 3. Add a registry to scan

OCIDex scans container registries itself. Point it at a public image on GitHub's registry:

1. Go to **Sources** in the sidebar, and choose **Add Registry**.
2. Fill in:

   | Field | Value |
   | --- | --- |
   | Name | `quickstart` |
   | Type | GitHub Container Registry (GHCR) |
   | Repositories | `dexidp/dex` |
   | Tag Patterns | `v2.45.?` |
   | Tags per repository | `3` |

   Leave everything else as it is. The form previews the tags this selects.
3. Save, then choose **Scan** on the new registry's row.

The scanner pulls each of the three images, generates an SBOM with syft, and ingests it. This
takes a minute or two.

## 4. Browse the SBOM

Go to **Artifacts**. `ghcr.io/dexidp/dex` appears as soon as its first SBOM is in. Open it.

- **Versions** lists one SBOM per version and architecture. Open one to see every package in it,
  its licenses, and its dependency tree.
- **Licenses** summarizes the licenses in the latest version.

Behind the scenes the enrichers are reading the image's labels and linking its source commit on
GitHub. Open an SBOM and look at its **Image** and **Git** tabs once they finish.

## 5. See its vulnerabilities

Open the artifact's **Vulnerabilities** tab.

On the first start, the vulnerability worker first downloads the grype vulnerability database,
which is a few GB, so findings can take several minutes to appear. After that a new SBOM is matched
within about a minute. The **Vulnerabilities** page in the sidebar lists findings across
everything you've scanned.

## 6. See what changed

Open the artifact's **Changelog** tab. Each entry compares one version with the one before it, and
lists the packages that were added, removed, upgraded or downgraded.

To compare any two SBOMs, choose **Compare SBOMs** and pick a **From** and a **To**. When the SBOM
has a dependency graph, the diff is drawn as a tree, so you can see which dependency each change
came in through.

## Stop or reset

```sh
make demo-down     # stop; your data is kept for next time
```

To start again from empty, also delete the demo's volumes:

```sh
OCIDEX_DEMO_SESSION_SECRET=unused \
  docker compose -f docker-compose.yml -f docker-compose.demo.yml down -v
```

## Next steps

- Fill the catalog with more images: create an API key under **Admin → API Keys**, then run
  `OCIDEX_API_KEY=ocidex_... make seed` (needs [nushell](https://www.nushell.sh/)). It registers
  a dozen well-labeled public repositories.
- Learn the ideas behind what you just saw in [Concepts](/concepts/overview/).
- Run OCIDex for real with the [operator guide](/guides/operate/overview/).
- Push SBOMs from your CI with the [integrator guide](/guides/integrate/overview/).
