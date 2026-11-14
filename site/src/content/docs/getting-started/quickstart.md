---
title: Quickstart
description: Run OCIDex on your machine, scan a public image and browse its SBOM, vulnerabilities and changelog.
sidebar:
  order: 1
---

This takes you from nothing to a running OCIDex with real SBOMs in it, in about fifteen minutes,
most of which is waiting for the first build. You'll scan the three newest releases of a public
image, then look at its packages, its vulnerabilities and what changed between versions.

The demo runs on your machine only. Its sign-in accepts anyone, so don't expose it to a network.

## Before you start

You need:

- **Docker** with Compose v2 (`docker compose version` works), and about 15 GB of free disk for
  the images, their build cache and the vulnerability database;
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
first build takes about five minutes. Later starts reuse it.

When it returns, open `http://localhost:3000` in your browser.

## 2. Sign in

Choose **Sign in**, then **Continue with mock**. The demo's sign-in is a mock identity provider
that lets you pick who you are. Pick **demo-admin**, the installation admin. (**demo-viewer** is an ordinary user, for when you
want to see what someone without admin rights sees.)

## 3. Add a registry to scan

OCIDex scans container registries itself. Point it at a public image on GitHub's registry:

1. Go to **Admin**, open the **Sources** tab, and choose **Add Registry**.
2. Fill in:

   | Field | Value |
   | --- | --- |
   | Name | `quickstart` |
   | Type | GitHub Container Registry (GHCR) |
   | Repositories | `dexidp/dex` |
   | Scan scope | Custom |
   | Tag Patterns | `v*.*.?` |
   | Tag order | Semantic version |
   | Tags per repository | `3` |

   Choosing GHCR fills in the URL. Leave everything else as it is. The form previews what this
   selects: about 15 images, because each release is built for five platforms.
3. Choose **Create**, then **Scan** on the new registry's row.

The scanner pulls each image, generates an SBOM with syft, and ingests it. This takes a minute or
two. The pattern `v*.*.?` picks plain releases like `v2.46.1` and skips variants like
`v2.46.1-alpine`.

## 4. Browse the SBOM

Go to **Artifacts**. `ghcr.io/dexidp/dex` appears as soon as its first SBOM is in. Open it.
The header shows its versions, its vulnerabilities and whether its images are signed (dex's are).

- **Versions** lists one SBOM per version and architecture. Open one to see every package in it,
  its licenses, and its dependency tree.
- **Licenses** summarizes the licenses in the latest version.

Behind the scenes the enrichers are reading the image's labels and linking its source commit on
GitHub. Open an SBOM and look at its **Image** and **Git** tabs once they finish.

## 5. See its vulnerabilities

Open the artifact's **Vulnerabilities** tab.

On the first start, the vulnerability worker downloads the grype vulnerability database first,
which takes a minute or two, and then matches everything already scanned. Until then the
artifact reads *not scanned*. After that a new SBOM is matched within about a minute. The **Vulnerabilities** page in the sidebar lists findings across
everything you've scanned.

## 6. See what changed

Open the artifact's **Changelog** tab. Each entry compares one version with the one before it, and
lists the packages that were added, removed, upgraded or downgraded. The chips above it pick the
architecture and base distribution to follow.

To compare any two SBOMs, choose **Compare SBOMs**. For **From**, search for `dex` and pick an
older version; for **To**, a newer one on the same architecture (`amd64`, say). Comparing across
architectures shows every package as removed and added. When the SBOM
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
