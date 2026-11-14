---
title: Sign-in and access
description: Configure GitHub and OIDC sign-in, the first admin, and who may sign up.
sidebar:
  order: 2
---

OCIDex signs users in through external identity providers. It has no passwords of its own.

## Providers

Configure GitHub, an OpenID Connect issuer, or both. The API refuses to start with neither,
rather than serve a sign-in page nobody can get past. `SESSION_SECRET` is always required: it
signs the cookies every provider's flow relies on.

Each provider has a permanent key: `github`, or `oidc:<name>`. Accounts are matched on that key
and the provider's subject id, **never on email**, so two providers that both know
`alice@example.com` don't merge into one account by accident.

### GitHub

Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` from a GitHub OAuth app, and
`GITHUB_REDIRECT_URL` (chart: `api.env.githubRedirectUrl`) to
`https://<your host>/auth/callback`, exactly as registered in the app. Setting only one of the
pair is a startup error, not a silent disable: half a credential pair is nearly always a typo.

With GitHub and `SIGNUP_MODE=open`, any GitHub account can sign in. See [who may sign
up](#who-may-sign-up) below.

### OpenID Connect

One implementation covers Google, Okta, Entra ID, Keycloak, Auth0, GitLab and any other compliant
issuer. Setting `OIDC_ISSUER_URL` is what turns it on.

| Variable | What to set |
| --- | --- |
| `OIDC_ISSUER_URL` | The URL that serves `/.well-known/openid-configuration`. It must match the tokens' `iss` claim exactly, and be `https://` in production. |
| `OIDC_CLIENT_ID` | The client id. |
| `OIDC_CLIENT_SECRET` | The client secret. Omit it for a public client; PKCE is always used. |
| `OIDC_REDIRECT_URL` | `https://<your host>/auth/callback`. |
| `OIDC_NAME` | The provider key's name, `oidc` by default. **Choose it before anyone signs in**: changing it later orphans every account made through this issuer. |
| `OIDC_SCOPES` | `openid,profile,email` by default. |

Discovery runs at startup, so a wrong issuer URL stops the API with a clear error instead of
showing a button that fails when clicked.

One redirect URL serves every provider, because the provider a sign-in started with travels in a
signed cookie. Only an issuer that insists on a distinct URI per client needs
`/auth/callback/oidc:<name>`.

## The first admin

Nothing creates an admin automatically. A fresh installation has none, and every new account
starts as a viewer. `BOOTSTRAP_ADMINS` (chart: `api.env.bootstrapAdmins`) lists the identities
that are made installation admin when they sign in:

```
github:1234567,oidc:corp:00u1abcd
```

- `github:<id>` takes the numeric GitHub user id: `gh api users/<login> --jq .id`.
- `oidc:<name>:<sub>` takes the issuer's `sub` claim, which may itself contain colons.

An account can be listed before it exists. The list only ever promotes: an admin demoted by hand
is promoted again at their next sign-in, until they are taken off the list. A malformed entry
stops the API at startup.

## Who may sign up

The defaults suit a public instance. For a company installation, tighten two settings:

| Setting | Default | For a private install |
| --- | --- | --- |
| `SIGNUP_MODE` (`api.env.signupMode`) | `open`: any identity a provider vouches for gets an account | `existing`: only accounts that already exist, plus `BOOTSTRAP_ADMINS`. Anyone else is refused at the callback. |
| `SELF_SERVICE_NAMESPACES` (`api.env.selfServiceNamespaces`) | `true`: any signed-in user may create a namespace | `false`: only global members and admins may create namespaces, or registries that create one |

There is no invitation flow yet. To admit someone under `existing`, open sign-up briefly, or use
an OIDC issuer that only vouches for your own people and leave sign-up open.

## Linking a second identity

A signed-in user can link another provider to their account under **Admin → Account**. OCIDex
never merges accounts: an identity already linked to a different account is refused, and so is
unlinking an account's last identity.

## Sessions and cookies

Sessions last `SESSION_MAX_AGE_DAYS` (7 by default) and are stored in Postgres, so a sign-in that
starts on one API replica can finish on another.

The session cookie's `SameSite` attribute is `SESSION_COOKIE_SAMESITE`, `lax` by default. That
works whenever the UI and the API share a registrable domain: `ocidex.example.com` and
`api.ocidex.example.com` are the same site. Set `none` only when the UI is on a different domain
altogether, or every API call from it will look signed out. `none` is accepted only in production,
where the cookie is also `Secure`.

## Access inside OCIDex

Once someone is signed in, what they can see and do is decided by their role in each namespace.
See [Namespaces and access](/concepts/namespaces-and-access/), and the full
[authorization matrix](/reference/authorization/).
