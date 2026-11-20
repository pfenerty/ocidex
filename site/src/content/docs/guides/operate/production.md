---
title: Production checklist
description: The settings to decide before an OCIDex installation faces real users.
sidebar:
  order: 3
---

Each row is a setting to decide before an installation faces real users, with the value to start
from. The chart's defaults already cover some of them, `ENVIRONMENT=production` in particular, so
treat this as a list to check, not a list of changes. Every variable is described in the
[configuration reference](/reference/configuration/).

## Production hardening checklist

**Identity and access**

| Setting | Chart value | Recommended | Why |
| --- | --- | --- | --- |
| `ENVIRONMENT` | `api.env.environment` | `production` (the chart default) | Turns on the production-only checks: encryption keys required, strict CORS, an https OIDC issuer, the exact post-login redirect. Never run a reachable install as `development`. |
| `SESSION_SECRET` | Secret | `openssl rand -hex 32` | Signs session and OAuth state cookies. Back it up separately from the database. |
| `BOOTSTRAP_ADMINS` | `api.env.bootstrapAdmins` | One or two named identities | A fresh install has no admin. List only the people who should be one, by stable subject id, never by email. |
| `SIGNUP_MODE` | `api.env.signupMode` | `existing` for a private install | `open` gives an account to anyone your identity provider vouches for, which with GitHub is anyone. |
| `SELF_SERVICE_NAMESPACES` | `api.env.selfServiceNamespaces` | `"false"` for a private install | Stops a global viewer from creating namespaces, or registries that create one. |
| `OIDC_ISSUER_URL` | Secret | An `https://` issuer | Required to be https in production. An issuer that vouches only for your own people is the simplest way to keep sign-up open safely. |

**Browser and perimeter**

| Setting | Chart value | Recommended | Why |
| --- | --- | --- | --- |
| `FRONTEND_URL` | `api.env.frontendUrl` | The public UI origin, `https://…` | In production the post-login redirect is exactly this URL. |
| `CORS_ALLOWED_ORIGINS` | `api.env.corsAllowedOrigins` | The UI origin only | Also decides which origins may send cookie-authenticated writes. `*` stops the API at startup in production. |
| `SESSION_COOKIE_SAMESITE` | `api.env.sessionCookieSameSite` | `lax` | Use `none` only when the UI and the API are on different registrable domains. |
| `TRUSTED_PROXY_CIDRS`, `TRUSTED_PROXY_HOPS`, `CLIENT_IP_HEADER` | `api.env.trustedProxyCidrs`, `api.env.trustedProxyHops`, `api.env.clientIpHeader` | The ingress range if it is fixed, else `trustedProxyHops: "1"` | Without one of them, every visitor shares the ingress's rate-limit budget. Read [client IPs behind a proxy](#client-ips-behind-a-proxy) before using the hop count or a header. |
| `AUTH_RATE_LIMIT`, `API_RATE_LIMIT_INGEST`, `API_RATE_LIMIT_HEAVY` | `api.env.authRateLimit`, `api.env.apiRateLimitIngest`, `api.env.apiRateLimitHeavy` | Keep the defaults (`30`, `120`, `120`) | Counted per replica, so the effective limit is the value times `api.replicas`. Raise the ingest limit for a busy CI key, rather than setting it to `0`. |
| HSTS | ingress or Gateway | `Strict-Transport-Security` at the TLS terminator | Neither the API nor the web tier sends it, because both listen on plain http behind TLS. |

**Data and network**

| Setting | Chart value | Recommended | Why |
| --- | --- | --- | --- |
| `DATA_ENCRYPTION_KEYS`, `DATA_ENCRYPTION_ACTIVE_KEY` | Secret | `k1:$(openssl rand -base64 32)`, `k1` | Required in production. Encrypts stored registry credentials and webhook secrets. Back the key up apart from the database. See [rotating the key](/guides/operate/maintenance/#rotating-the-credential-encryption-key). |
| `EGRESS_ALLOW_PRIVATE` | `egressGuard.allowPrivate` | `false` | The API and workers dial registry URLs that users supply. Leave private ranges refused. |
| `EGRESS_ALLOW_CIDRS`, `EGRESS_DENY_CIDRS` | `egressGuard.allowCidrs`, `egressGuard.denyCidrs` | Allow only the in-cluster registry hosts you need | Narrow exceptions are safer than `EGRESS_ALLOW_PRIVATE=true`. See [egress policy](#egress-policy). |
| NetworkPolicy | `networkPolicy.enabled` | `true`, with `egress.database` and `ingress.from` set | The network-level backstop to the egress checks in code. See [network policy](#network-policy). |
| `METRICS_ADDR` | fixed `:9090` | Never routed through the ingress | Metrics are on a separate listener. Scrape it in-cluster; don't expose it. |
| `RETENTION_MODE` | `api.env.retention.mode` | `dry-run` first, then `on` | Bounds database growth. Read a dry run's log before turning it on. See [retention](/guides/operate/maintenance/#sbom-retention). |

How to report a vulnerability, and which versions get fixes, is in the project's
[security policy](https://github.com/pfenerty/ocidex/blob/main/SECURITY.md).

## Client IPs behind a proxy

Rate limits key anonymous requests by client IP, so behind a proxy OCIDex has to be told how far to
believe what the proxy reports. Three settings do this, applied in this order:

1. **`TRUSTED_PROXY_CIDRS`, when set, gates everything.** A direct peer outside these ranges is the
   client, whatever headers it sent. It's the strictest option, and the only one a client can't
   route around.
2. **`CLIENT_IP_HEADER`, when set, is read next.** Its value is the client. A missing or
   unparseable value means the request didn't pass the edge that sets it, and the peer is the
   client.
3. **Otherwise `TRUSTED_PROXY_HOPS`, when set:** the client is the Nth `X-Forwarded-For` entry from
   the right.
4. **Otherwise, with only `TRUSTED_PROXY_CIDRS`,** the chain is walked right to left while it stays
   inside the trusted ranges.

`CLIENT_IP_HEADER` and `TRUSTED_PROXY_HOPS` describe your topology, not addresses. **They are safe
only if no path reaches the API without passing through those proxies.** A client that can reach
the API's Service, a NodePort or the pod directly can send any header it likes and pick its own
rate-limit key. Add `TRUSTED_PROXY_CIDRS` on top when you can.

## Egress policy

Registry URLs come from users, so every process that dials them (the API, the scanner and the
enrichers) checks the resolved address of each connection. By default they refuse private ranges
(`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `198.18/15`, `fc00::/7`, and the NAT64
local-use prefix `64:ff9b:1::/48`). They always refuse loopback, link-local (which includes cloud
metadata endpoints), multicast, the reserved and IETF-assigned IPv4 ranges, and Teredo. An IPv6
address that carries an IPv4 address (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) is
judged as that IPv4 address, so a NAT64 gateway on an IPv6-only cluster reaches only what the
IPv4 rules allow.

To scan a registry inside your cluster or network, allow just its address with
`egressGuard.allowCidrs`. Prefer this to `egressGuard.allowPrivate: true`, which opens every
private range, including the Kubernetes API, Postgres, NATS and OCIDex's own pods. If you do set
it, pair it with `egressGuard.denyCidrs` naming the cluster's service and pod CIDRs. The chart sets the same policy on every
component. `HTTP_PROXY` and `HTTPS_PROXY` are honoured, and then the proxy's address is what's
checked.

On ingest, the API also checks the registry of an uploaded container SBOM's image, so an SBOM
naming a refused address is rejected.

## Network policy

Each chart ships plain `networking.k8s.io/v1` NetworkPolicies, off by default. The chart knows
which of its components talks to which; you supply the peers only you know.

| Chart | Value | What it is |
| --- | --- | --- |
| `ocidex` | `networkPolicy.egress.database` | Postgres (**required**), as `NetworkPolicyPeer`s |
| `ocidex` | `networkPolicy.ingress.from` | The Gateway or Ingress pods that reach the API and web |
| `ocidex` | `networkPolicy.ingress.apiFrom` | In-cluster API clients, like the operator and the agent |
| `ocidex` | `networkPolicy.ingress.metricsFrom` | Prometheus and KEDA |
| `ocidex` | `networkPolicy.egress.internet.except` | Ranges carved out of internet egress; defaults cover RFC 1918, CGNAT and link-local |
| operator, agent | `networkPolicy.egress.server` | The OCIDex API (**required**) |
| operator, agent | `networkPolicy.egress.apiServer` | The Kubernetes API server's endpoints, as ipBlocks |

With the policy on, every pod is denied by default in both directions, and may reach the release's
own pods and DNS. The components that need Postgres may reach it, and those that dial registries
may reach the internet minus `except`. The web tier and NATS reach nothing outside the release.
An in-cluster registry or identity provider goes in `networkPolicy.extraEgress`.

On Cilium, an ipBlock never matches the Kubernetes API server. Leave `egress.apiServer` empty and
add a `CiliumNetworkPolicy` with `toEntities: [kube-apiserver]` beside the operator and agent.

## Security headers

The web tier sends a Content-Security-Policy, `X-Content-Type-Options`, `Referrer-Policy` and
`Permissions-Policy`. The CSP's `connect-src 'self'` assumes the UI reaches the API on its own
origin, as the routing in [Install](/guides/operate/install/#routing) arranges. The API sends
`nosniff` everywhere and `Cache-Control: no-store` on authentication routes. Neither sends HSTS: set
it at your TLS terminator.

## High availability

The chart runs two API replicas, with a PodDisruptionBudget and a topology spread, so a node
drain keeps one up. Readiness checks the database, so a replica that loses Postgres stops getting
traffic. Every background loop in the API is safe at any replica count: the registry poller,
retention sweep and provenance reverifier are leader-elected, and the rollup refresher takes a
lock.

Migrations run in their own Job, never at API startup.
