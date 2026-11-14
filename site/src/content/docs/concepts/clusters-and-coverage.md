---
title: Clusters and coverage
description: What OCIDex knows about what is running, and what it can't see.
sidebar:
  order: 7
---

Registry scans tell you what was built. A **cluster** tells you what is running.

Register a Kubernetes cluster in a namespace, install the `ocidex-k8s-agent` in it, and the agent
sends OCIDex a snapshot of every running container and its image digest. Each snapshot replaces
the last.

## Coverage

OCIDex can only speak to images it has an SBOM for. **Coverage** is how much of the cluster that
is, and the cluster page always shows it, split three ways:

| State | Meaning |
| --- | --- |
| **Matched** | The image's digest matches an ingested SBOM. These are assessed. |
| **No SBOM** | The digest is valid, but nothing has been ingested for it yet. |
| **Unresolvable** | The container runtime reported no registry digest, so there is nothing to match. |

Counts are of **workload containers**: one per namespace, workload, container and image. A
Deployment with three replicas is one container.

A vulnerability count on the cluster page never appears without its coverage. If 40 of 100
containers are matched, the vulnerability figures describe those 40, and the other 60 are *not
assessed*, which is not the same as clean.

## Closing the gap

With **auto-ingest** on, which is the default, every snapshot queues a scan of each running image
that has no SBOM. OCIDex pulls it with the credentials of a registry in the same namespace that
serves it, or anonymously when none does. Running images are also protected from retention, so
what's running stays answerable.
