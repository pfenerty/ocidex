---
title: Troubleshooting
description: Diagnose and fix the common problems with an OCIDex installation.
sidebar:
  order: 11
---

## Installation

| Symptom | First thing to check |
| --- | --- |
| Pods stuck in `CreateContainerConfigError` | `kubectl describe pod`: usually the Secret is missing, or `existingSecret` doesn't match its name. |
| The API crash-loops at startup | `kubectl logs deploy/<release>-api`. It names the missing or invalid setting: `DATABASE_URL`, no identity provider, a malformed `BOOTSTRAP_ADMINS`, `CORS_ALLOWED_ORIGINS` of `*` in production, an OIDC issuer that doesn't answer discovery, missing encryption keys. |
| Sign-in returns `redirect_uri_mismatch` | The redirect URL (`api.env.githubRedirectUrl`, or `OIDC_REDIRECT_URL`) doesn't exactly match what's registered with the provider. |
| `/api` or `/auth` returns the UI, or 404 | Nothing routes them to the API. The web container has no reverse proxy. See [Routing](/guides/operate/install/#routing), and check the API paths come before the `/` catch-all. |
| The UI loads but every page says you're signed out | The UI and the API are on different registrable domains: set `SESSION_COOKIE_SAMESITE=none`. Or `CORS_ALLOWED_ORIGINS` doesn't list the UI's origin. |
| Everyone gets `429 Too Many Requests` together | Behind an ingress, every visitor shares one client IP. Set one of the [client IP settings](/guides/operate/production/#client-ips-behind-a-proxy). |
| Gateway returns 502 for a ready pod | The route's backend name or port is wrong. The Services are `<release>-api` and `<release>-web`, on port 80. |
| NATS won't schedule | `nats.storage.storageClass` must name a class the cluster has, or set `nats.storage.emptyDir: true`. |

### The migrate Job fails

A failed migrate Job blocks the whole install or upgrade. Read its logs with
`kubectl logs job/<release>-migrate-<revision> --all-containers`. The usual causes:

- **`DATABASE_URL` is wrong**, or the database isn't ready yet.
- **Objects owned by another role.** If someone ran DDL on the database by hand, some objects may
  belong to a different role. The Job fails before touching the schema, and prints the
  `ALTER ... OWNER TO` statements to run as a superuser.
- **Missing encryption keys** in production.
- **A missing extension permission**: the application role must be able to create the extensions
  the migrations use, such as `pgcrypto`.

The Job's pods are deleted a few minutes after a failure. `ocidex migrate audit` in a throwaway pod
repeats the ownership check, read-only.

## Scans and enrichment

### The queue isn't draining

The queued count on **Admin → System Status** grows or doesn't move.

- **Is the scanner ready?** `kubectl get pods -l app.kubernetes.io/component=scanner-worker`. Not ready
  means it lost NATS *and* the database is slow to answer.
- **Is it being OOMKilled?** Check `RESTARTS` and `kubectl describe pod` for `OOMKilled`. Raise
  `scannerWorker.resources.limits.memory`, or lower `SCANNER_MAX_CONCURRENCY`.
- **Is the database reachable?** The worker logs errors when it can't claim a job.

A NATS outage is not on this list. Workers fall back to polling the database every 30 seconds, so
the queue keeps draining, just with a little more latency. Fix NATS at your own pace.

### A job keeps retrying with no error

A job whose attempt count climbs while its last error stays empty is the worker being killed, not
the scan failing: almost always an OOMKill on an oversized image, which also takes down every other
scan in that pod. Raise the scanner's memory limit if the image is worth scanning, or lower
`SCANNER_MAX_IMAGE_BYTES` so it's refused from its manifest instead.

Jobs left `running` by a pod that died are requeued automatically after `SCANNER_STUCK_THRESHOLD`
(15 minutes by default), or failed once their attempts run out.

### Failed jobs pile up

Filter the **Jobs** page to `failed`. Each job shows the error that stopped it:

| Error | Meaning |
| --- | --- |
| `manifest unknown`, `404` | The image was deleted before it was scanned. Nothing to do. |
| `connection refused` | The registry was down. Retry once it's back. |
| `egress denied` | The registry's address is blocked by the [egress policy](/guides/operate/production/#egress-policy). |
| `image too large to scan` | It's over `SCANNER_MAX_IMAGE_BYTES`. Raise the ceiling and the memory limit together, or leave it. |
| `stuck: worker did not complete and retries exhausted` | It never finished: usually an image syft can't handle, or one that keeps OOMKilling the worker. |
| `syft: …` | syft itself failed on the image. Please [report it](https://github.com/pfenerty/ocidex/issues). |

**Retry** puts a failed job back in the queue. A registry poll won't retry it for you, so a
permanently broken image doesn't re-run on every poll.

### Re-scan one image

```sh
curl -X POST "https://ocidex.example.com/api/v1/registries/$REGISTRY_ID/scan" \
  -H "Authorization: Bearer $OCIDEX_API_KEY" -H "Content-Type: application/json" \
  -d '{"repository":"acme/api","digest":"sha256:…","tag":"1.4.2"}'
```

A scan of a digest that's already queued or running isn't duplicated.

## The operator

### A namespace stuck Terminating

A Kubernetes namespace sits in `Terminating`, and its conditions name
`ocidex.io/registry-protection` finalizers. The operator only removes the finalizer from
`OCIRegistry` objects in namespaces it watches. These are outside its `watchNamespace`, usually
because it was retargeted or uninstalled before they were deleted.

Check whether each one ever registered:

```sh
kubectl get ociregistries -n <ns> \
  -o custom-columns='NAME:.metadata.name,REGID:.status.registryID'
```

- **`REGID` empty:** it never registered. Removing the finalizer by hand is exactly what the
  operator would have done:

  ```sh
  kubectl patch ociregistry <name> -n <ns> --type=merge -p '{"metadata":{"finalizers":null}}'
  ```

- **`REGID` set:** delete the registry in OCIDex first (in the UI, or
  `DELETE /api/v1/registries/<id>`), then remove the finalizer. Doing it the other way round leaves
  the registry in OCIDex with nothing managing it.

The namespace finishes deleting within seconds of the last finalizer going.
