---
title: Install with Helm
description: Install OCIDex on Kubernetes with the Helm chart.
sidebar:
  order: 1
---

This installs OCIDex into the namespace `ocidex`, reachable at `https://ocidex.example.com`.
Substitute your own names throughout.

## 1. Prepare the database

Create a database and a role that owns it:

```sql
CREATE ROLE ocidex LOGIN PASSWORD '...';
CREATE DATABASE ocidex OWNER ocidex;
```

The role needs to own the schema, because migrations create and alter tables. OCIDex reaches the
database through `DATABASE_URL`, either a URL (`postgres://ocidex:...@db:5432/ocidex`) or a libpq
keyword string (`host=db port=5432 dbname=ocidex user=ocidex password=... sslmode=require`).

With CloudNativePG, a `Cluster` with `bootstrap.initdb.owner: ocidex` gives you exactly this, and
its `-rw` Service is the host.

## 2. Register an identity provider

OCIDex has no passwords of its own. Users sign in through GitHub, an OpenID Connect issuer, or
both. You need at least one.

- **GitHub**: create an OAuth app (GitHub → Settings → Developer settings → OAuth Apps) with the
  callback URL `https://ocidex.example.com/auth/callback`. Keep its client ID and secret.
- **OIDC** (Google, Okta, Entra ID, Keycloak, Auth0, GitLab and others): register a client with
  the redirect URI `https://ocidex.example.com/auth/callback`. Keep the issuer URL and client ID,
  and the client secret if it has one.

[Sign-in and access](/guides/operate/authentication/) covers the options.

## 3. Create the Secret

Everything sensitive lives in one Secret, which the chart mounts into every pod. Its name is
`existingSecret` in the values (`ocidex-secrets` by default).

```sh
kubectl create namespace ocidex
kubectl -n ocidex create secret generic ocidex-secrets \
  --from-literal=DATABASE_URL='postgres://ocidex:...@db:5432/ocidex' \
  --from-literal=SESSION_SECRET="$(openssl rand -hex 32)" \
  --from-literal=DATA_ENCRYPTION_KEYS="k1:$(openssl rand -base64 32)" \
  --from-literal=DATA_ENCRYPTION_ACTIVE_KEY=k1 \
  --from-literal=GITHUB_CLIENT_ID=... \
  --from-literal=GITHUB_CLIENT_SECRET=...
```

For OIDC, use `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and
`OIDC_REDIRECT_URL=https://ocidex.example.com/auth/callback` in place of, or as well as, the GitHub
pair.

- `SESSION_SECRET` signs session cookies.
- `DATA_ENCRYPTION_KEYS` encrypts the registry credentials OCIDex stores. It is required in
  production.

**Back up both somewhere other than the database backup.** Losing the session secret signs
everyone out. Losing the encryption key means re-entering every registry's credentials. Keep the
Secret itself in your usual secret store (SOPS, External Secrets, Sealed Secrets), not in plain
YAML in Git.

## 4. Write the values

```yaml title="values.yaml"
existingSecret: ocidex-secrets

api:
  env:
    frontendUrl: https://ocidex.example.com
    corsAllowedOrigins: https://ocidex.example.com
    githubRedirectUrl: https://ocidex.example.com/auth/callback
    # Who becomes installation admin at first sign-in. See "The first admin" below.
    bootstrapAdmins: "github:1234567"

# Route the UI and the API on one hostname (Gateway API).
gatewayApi:
  enabled: true
  gatewayName: my-gateway
  gatewayNamespace: gateway-system
  webHostname: ocidex.example.com
  apiHostname: api.ocidex.example.com

nats:
  storage:
    storageClass: standard

vulnWorker:
  db:
    persistence:
      storageClass: standard   # node-local storage, not NFS
```

For OIDC, the chart has no value for the redirect URL. Add `OIDC_REDIRECT_URL` to the Secret
instead: the chart mounts every key in it as an environment variable. Every value is listed in the
[Helm values reference](/reference/helm-values/).

### Routing

The web container serves the UI's static files and nothing else. Something in front of it has to
send `/api`, `/auth`, `/health` and `/ready` to the API Service, so the UI and the API share an
origin.

- **Gateway API**: `gatewayApi.enabled: true` creates the routes, with the API paths ahead of the
  catch-all. It also gives the API a hostname of its own for API clients.
- **Ingress**: add rules for those four paths to the `<release>-api` Service, ahead of `/` to the
  `<release>-web` Service. Both Services listen on port 80.

Rule order matters on controllers that flatten routes into a first-match list, Cloudflare Tunnel
among them: put the API paths first.

## 5. Install

```sh
helm upgrade --install ocidex oci://ghcr.io/pfenerty/charts/ocidex \
  --namespace ocidex --version <version> -f values.yaml
```

Before any pod starts, a Job runs the database migrations. The install fails, and nothing else
rolls out, if they fail.

## 6. Check it

```sh
kubectl -n ocidex get pods        # everything Running and Ready
curl -fsS https://ocidex.example.com/health
curl -fsS https://ocidex.example.com/ready     # checks the database
```

Then open `https://ocidex.example.com` and sign in.

## The first admin

A fresh installation has no admin, and every new account starts as an ordinary viewer.
`api.env.bootstrapAdmins` lists the identities that become installation admin when they sign in,
by their provider's stable user id, never by email:

- GitHub: `github:<numeric user id>`. Find yours with `gh api users/<login> --jq .id`.
- OIDC: `oidc:<name>:<sub claim>`, where `<name>` is `OIDC_NAME` (`oidc` by default).

Sign in as one of them, then create a namespace, add a registry and give other people roles from
the UI.

## Next steps

- Go through the [production checklist](/guides/operate/production/) before anyone else uses it.
- To see what's running in your clusters, install the [inventory agent](/guides/operate/clusters-and-operator/).
- To follow releases automatically with Flux, see [Upgrade](/guides/operate/upgrade/#following-releases-with-flux).
