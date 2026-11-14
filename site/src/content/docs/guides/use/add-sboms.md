---
title: Add SBOMs
description: Get SBOMs into OCIDex by scanning a registry or uploading them.
sidebar:
  order: 1
---

SBOMs reach OCIDex through a [source](/concepts/sources-and-registries/): a registry OCIDex scans,
an upload source you push to, or a cluster. Which namespace a source belongs to decides who can see
what comes through it.

## Scan a registry

Go to **Sources** and choose **Add Registry**.

| Field | What to enter |
| --- | --- |
| **Name** | A label, like `acme-ghcr`. |
| **Namespace** | The namespace it belongs to. Leave it empty to create a namespace named after the registry. |
| **Type** | Docker Hub, GHCR, Harbor, Zot or a generic OCI registry. Docker Hub and GHCR fill in the URL. |
| **URL** | The registry host, like `registry.example.com:5000`. No path. |
| **Auth Username**, **Auth Token** | Credentials, for a private registry. They're stored encrypted. |
| **Repositories** | An explicit list, one per line. Required for registries that don't list their catalog, like Docker Hub, GHCR and Quay. |
| **Repository Patterns** | Or glob patterns matched against the catalog, like `team-a/*`. |
| **Tag Patterns** | Globs for tags to consider, like `v1.*`. `*` runs to the end of the tag and `?` matches one character. |
| **Tags per repository** | How many of the newest tags to scan in each repository. 50 by default; 0 is unlimited. |
| **Tag order** | How "newest" is decided: semver, image creation time, or alphabetical. Auto picks semver when your patterns name versions. |
| **Max tag age** | Optionally skip images older than this many days. |
| **Scan Mode** | **Poll** checks on an interval; **Webhook** waits for the registry to call OCIDex; **Both**. |
| **Visibility** | Whether the registry is listed publicly. |
| **Verification Mode** | Optionally check image signatures, against a public key or a keyless identity. |

The form previews which tags your settings select before you save, so you can see what a pattern
does without waiting for a scan.

Save, then choose **Scan** on the registry's row to start now rather than waiting for the poll.
Each selected image is pulled, scanned with syft and ingested, one SBOM per platform. Follow
progress on the **Jobs** page (admins) or wait for the artifacts to appear.

### Webhooks

In **Webhook** or **Both** mode, the registry tells OCIDex when something is pushed, so new
images are scanned within seconds. Saving the registry shows its webhook secret **once**: copy it
then. Configure the registry to `POST` push events to `/api/v1/registries/<registry id>/webhook`
with the header `Authorization: Bearer <secret>`. The body names the pushed image: `name`,
`reference`, `digest` and `mediaType`, the shape Zot's notifications use.

### Scanning a private network

OCIDex refuses to reach private addresses by default, so a registry inside your network fails with
`egress denied` until an operator allows its address. See [Egress
policy](/guides/operate/production/#egress-policy).

## Upload SBOMs

Upload an SBOM you made yourself, for instance in CI, or for something that isn't a container
image. First create an upload source in the namespace it should land in:

```sh
ocidex-cli source create --name ci --namespace acme
```

Then push to it with `ocidex-cli sbom push`, or `POST /api/v1/sboms`. [Push SBOMs from
CI](/guides/integrate/ci/) has recipes, and [the API page](/guides/integrate/api/#uploading-an-sbom)
lists every parameter.

OCIDex accepts **CycloneDX JSON**. Uploading the same image digest twice stores it once.

## What makes a good SBOM

The more an SBOM says, the more OCIDex can do with it:

- **Package URLs on every component**, so diffs match packages exactly.
- **A dependency graph**, so diffs draw a tree.
- **For container images: a version, an architecture and a build date**, which OCIDex requires.
  They come from your image's labels; see [Label your images](/guides/use/image-labels/).

A recent syft gives you all of these.
