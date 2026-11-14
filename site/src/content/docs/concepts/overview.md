---
title: How OCIDex works
description: The pieces of OCIDex and how an SBOM moves through them.
sidebar:
  order: 0
---

OCIDex is a catalog of software bills of materials (SBOMs). It collects CycloneDX SBOMs for your
container images and other software, keeps every version of them, and answers three questions
about what you build and run:

- **What is in it?** Every package, version and license, across every artifact.
- **What changed?** Between any two versions of an artifact, as a dependency tree or a flat list.
- **What is vulnerable?** Matched against a daily vulnerability database, and re-matched when a
  new advisory appears, with no rescan.

## The moving parts

OCIDex is a set of processes around one PostgreSQL database.

| Process | What it does |
| --- | --- |
| **API** | Serves the REST API, sign-in and SBOM upload. The only process users talk to. |
| **Web** | The single-page UI, served by nginx. |
| **scanner-worker** | Walks container registries, runs [syft](https://github.com/anchore/syft) on each selected image and ingests the SBOM. |
| **Enricher workers** | Add facts an SBOM doesn't carry: image labels, the source commit, signatures. |
| **vuln-worker** | Keeps vulnerability matches current against the grype database. |
| **NATS JetStream** | Wakes workers when a job is waiting. Postgres holds the jobs themselves. |
| **k8s-agent** | Optional. Runs in a Kubernetes cluster and reports what it is running. |
| **Operator** | Optional. Manages registries, scans and API keys as Kubernetes resources. |

Slow or external work, like pulling an image, calling GitHub or matching vulnerabilities, always
runs in a worker. A request never waits on a registry.

## The life of an SBOM

1. **It arrives.** An SBOM comes from one of three places: a [registry scan](/concepts/sources-and-registries/),
   an upload (from CI, `ocidex-cli` or the API), or a [cluster's running images](/concepts/clusters-and-coverage/).
2. **It is stored.** OCIDex attaches it to an [artifact](/concepts/artifacts-and-sboms/), and stores
   it with its components, dependency graph and licenses in one transaction.
3. **It is enriched.** Each [enricher](/concepts/enrichment/) gets a job, and adds what it can find.
   Ingest doesn't wait for them.
4. **It is matched.** Within about a minute the vuln-worker [matches](/concepts/vulnerabilities/)
   its packages against the vulnerability database.
5. **It is compared.** Its artifact's changelog and any [diff](/concepts/diffs-and-changelog/) now
   include it.

Who can see it depends on the [namespace](/concepts/namespaces-and-access/) it belongs to.
