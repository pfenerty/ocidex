---
title: Operator guide
description: Install, configure, upgrade, size and operate OCIDex on Kubernetes.
sidebar:
  order: 0
---

OCIDex runs on Kubernetes, installed from Helm charts. This guide takes you from an empty
cluster to a production installation, and covers running it from then on.

## What you deploy

| Chart | What it installs | Where |
| --- | --- | --- |
| `ocidex` | The API, web UI, NATS, scanner, enrichers, vuln-worker and a migration Job | Once, in the cluster that runs OCIDex |
| `ocidex-k8s-agent` | The inventory agent | Once in each cluster OCIDex should see, optional |
| `ocidex-operator` | Manages registries, scans and API keys as Kubernetes resources | Optional, alpha |

All three are published to `oci://ghcr.io/pfenerty/charts`. The images are multi-arch
(`linux/amd64`, `linux/arm64`) and signed.

You bring:

- **Kubernetes**. Every pod the charts render passes the PodSecurity `restricted` profile.
- **PostgreSQL**. OCIDex is tested against PostgreSQL 18. The chart doesn't run a database,
  because that's a platform concern: use CloudNativePG, a managed database, or one you already
  run.
- **A way in**: a Gateway API implementation or an Ingress controller, and TLS.
- **An identity provider**: a GitHub OAuth app, or any OpenID Connect issuer.

## The pages

1. [Install with Helm](/guides/operate/install/): the Secret, the values and the first sign-in.
2. [Sign-in and access](/guides/operate/authentication/): GitHub, OIDC, the first admin and who may
   sign up.
3. [Production checklist](/guides/operate/production/): the settings to decide before real users
   arrive.
4. [Scanning and workers](/guides/operate/workers/): the scanner, the enrichers, the vulnerability
   worker and how to scale them.
5. [Clusters and the operator](/guides/operate/clusters-and-operator/): installing the inventory
   agent and the operator.
6. [Upgrade](/guides/operate/upgrade/): upgrade paths, per-version steps and rolling back.
7. [Back up and restore](/guides/operate/backup/).
8. [Routine maintenance](/guides/operate/maintenance/): retention, key rotation and backfills.
9. [Monitoring](/guides/operate/monitoring/): health checks, metrics, alerts and tracing.
10. [Sizing](/guides/operate/sizing/): how big the database gets and how fast it answers.
11. [Troubleshooting](/guides/operate/troubleshooting/).
12. [Verify release artifacts](/guides/operate/verify-artifacts/).

Every environment variable is in the [configuration reference](/reference/configuration/), and
every chart value in the [Helm values reference](/reference/helm-values/).
