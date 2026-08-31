---
status: "accepted"
date: 2026-08-30
decision-makers: Patrick Fenerty
---

# Provider-agnostic identity with generic OIDC

## Context and Problem Statement

Until `ocidex-iqkt`, "who is signed in" was spelled `github_id`. Migration 00007 gave
`ocidex_user` a `github_id BIGINT NOT NULL UNIQUE` and a `github_username TEXT`, and that
pair was the account's only external key. The consequence was not merely a naming
problem: it made the statement *a user is a GitHub account* structurally true. A person
who does not have a GitHub account could not exist in the system, and a person who has one
could not also sign in any other way.

The column names then propagated upward. The repository selected them, the service
returned them, the API serialised them, the OpenAPI document declared them, and the
frontend rendered `user.github_username` in the sidebar, the persona switcher, the members
table and the dashboard greeting. Adding a second issuer therefore meant editing every one
of those layers, which is exactly the cost that keeps a single-issuer assumption in place
once it is made.

The forcing function was deployment. OCIDex is meant to run inside an organisation's own
cluster, and organisations that run their own registries generally run their own IdP —
Entra, Okta, Keycloak, Google Workspace. Requiring every one of their engineers to hold a
personal github.com account, and requiring an administrator to register an OAuth app on a
third party's SaaS, is a real barrier to the only deployment shape the project targets.

A secondary problem was that the `/auth` routes had nothing exercising them. The dev rig
authenticates by API key and no shared GitHub OAuth app exists to point a developer at, so
sign-in, session issuance and the callback were verifiable only by hand against a personal
OAuth app.

## Decision Drivers

* **A person is not an account at one issuer.** The data model must let one person reach
  one OCIDex account through more than one issuer, and must let an account exist with no
  GitHub identity at all.
* **Adding an issuer must not be a schema change.** The cost of the second issuer was paid
  in this epic; the third must cost a configuration block.
* **No issuer's name may appear above the `auth` package.** The service, API, OpenAPI
  document and frontend must be able to state what they mean without naming a vendor.
* **Account takeover must be structurally impossible, not merely unlikely.** Whatever key
  matches a sign-in to an existing account has to be something an issuer cannot be tricked
  into asserting about someone else.
* **The sign-in path must be testable without a third party.** A protocol that can be
  mocked is worth more here than one that cannot.
* **Existing installations must not lose their sessions.** Every account created under the
  GitHub-shaped schema keeps working, without a re-link step.

## Considered Options

* Generic OIDC as a second provider behind an internal `Provider` interface
* Hand-written adapters per identity provider (Google, Okta, Entra, Keycloak, …)
* SAML 2.0
* An external identity broker (Dex, Keycloak-as-proxy) in front of OCIDex

## Decision Outcome

Chosen option: **generic OIDC as a second provider behind an internal `Provider`
interface**, because one implementation of a conformance-tested protocol covers every IdP
the target deployments actually run, and the interface keeps GitHub — which is *not* an
OIDC issuer here — from being a special case anywhere above `internal/auth`.

### Rule I1 — Identity is a table, not a column

`user_identity(user_id, provider, subject)` with `UNIQUE (provider, subject)` holds the
credentials an account may be reached by. `ocidex_user` keeps `display_name`, `email` and
`role`, because those are properties of the *account* rather than of any credential used
to reach it: linking a second identity must not change who the account displays as.

One account may hold many identities; one identity belongs to exactly one account. That is
the shape `NOT NULL UNIQUE` on a column cannot express and is the whole reason for the
table.

`provider` is the issuer key: `github`, or `oidc:<name>` for a generic issuer. GitHub keeps
its bare name rather than becoming `oidc:github` because it is genuinely not an OIDC issuer
in this system — it is exchanged through the plain OAuth2 user API and its subject is the
numeric user id as text. Generic issuers are namespaced so that two deployments' issuers
cannot collide on a bare subject.

The provider key is **permanent**. Changing `OIDC_NAME` after the first sign-in orphans
every account that arrived through that issuer, because the key half of their identity row
no longer matches anything configured.

### Rule I2 — The subject is the only match key; email never is

An identity is matched on `(provider, subject)` and on nothing else. `subject` is the
issuer's stable identifier — GitHub's numeric id, OIDC's `sub` claim — chosen because it
survives a rename and an address change.

Email is stored as advisory display data and is **never** used to find an existing account.
Matching on email would mean that any configured issuer which does not verify addresses —
or which lets a user set an arbitrary one — could take over an account created at a
different issuer merely by asserting its address. `email_verified` does not fix this: it is
the issuer's claim about its own diligence, and the whole point of supporting several
issuers is that they are not equally diligent.

The corollary is that the same human arriving through a second issuer gets a *second
account*, not the first one. Rule I4 is how they are joined.

### Rule I3 — One `Provider` interface, PKCE for everyone

`internal/auth.Provider` is three methods: `Name()`, `AuthURL(state, verifier)` and
`Exchange(ctx, code, verifier) (Identity, error)`. `Identity` is
`{Provider, Subject, Email, DisplayName}`. Nothing above this package knows an issuer's
name, and the service layer's job reduces to "resolve this `Identity` to an account".

A PKCE verifier is minted for every sign-in regardless of provider and threaded through
both methods. GitHub's provider ignores it. Making the verifier part of the interface from
the start meant adding the OIDC provider was an addition rather than a change to a shared
signature.

The verifier travels in the signed `securecookie` state cookie, never to the issuer. The
same cookie carries the provider a sign-in began with, and **the cookie is the authority at
callback time, not the URL** — a caller who could name the provider at the callback could
otherwise present a code minted by a weak issuer against an account created by a strong
one. One registered redirect URI therefore serves every issuer.

OIDC discovery runs at **startup**, not on first click, so a wrong `OIDC_ISSUER_URL` stops
the process with a clear error instead of producing a login button that 500s.

**No provider is individually mandatory; the list being non-empty is.** GitHub, OIDC, or
both — `buildIdentityProviders` refuses to start only when it would end up with nothing,
because a server with an empty provider list can mint no session and presents its failure
as a login page with no buttons on it. `SESSION_SECRET` is required in every case: it signs
the cookies every provider's flow depends on. Half a GitHub credential pair is a startup
error rather than a silent disable, since one var without the other is a typo far more
often than an intent to turn GitHub off.

### Rule I4 — Linking is explicit, and a conflict is a 409 that never merges

An authenticated user starts a link from the account page. It runs the same OAuth round
trip as a sign-in and is distinguished only by a field in the signed state cookie: on
return, a link-flavoured state writes a `user_identity` row for the *current session's*
account instead of resolving a session from the identity.

If the returned `(provider, subject)` is already linked to a different account, the answer
is **409 Conflict and no write**. OCIDex does not merge accounts. A merge would have to
decide what happens to the two accounts' namespace memberships, API keys, watches and
audit history, and getting that wrong silently grants access rather than denying it —
whereas refusing is recoverable by an administrator in a way an unwanted merge is not.

Unlinking the account's **last** identity is also a 409. An account with no identities
cannot be signed into by anyone and can only be repaired with SQL.

The callback that finishes a link requires a live session; without one it is a 401, so the
link seam cannot be driven by a bare authorization code.

### Rule I5 — GitHub-shaped columns leave the schema, in two migrations

00069 creates `user_identity`, backfills every existing account's `('github', <id>)` pair,
and leaves `github_id`/`github_username` in place but nullable. 00070 drops them. The gap
between the two is deliberate: it is the window in which a rollback to the previous binary
still finds the columns it reads.

Migrations 00007 and 00008 are left exactly as they were. 00008 seeds the bootstrap admin
by `github_id` into a table that, at that point in history, still has the column; 00069's
backfill then converts that row into an identity. A fresh replay of the whole sequence and
an upgraded database therefore arrive at the same state, which is the property that would
be lost by rewriting an applied migration to say something it never said.

### Rule I6 — The mock issuer ships nowhere

`internal/devidp` is a real OIDC issuer implementation used by the dev rig
(`scripts/dev-auth.sh`) and by `tests/oidc_integration_test.go`. It signs with a key
generated at startup, accepts any `client_id`, and hands a session to whoever names a
subject. That is harmless on a laptop and a complete authentication bypass in a cluster.

It is reachable only through `cmd/mock-idp`, no production binary imports it, and
`TestMockIDPShipsInNoImage` reads `docker/Dockerfile` and fails the build if the string
`mock-idp` appears in it. The guard is a test rather than a convention because the failure
mode is silent.

### Consequences

* Good, because an installation can now run with its own IdP, and adding a fourth or
  fifth is a configuration block rather than a code change or a migration.
* Good, because the `/auth` routes are finally under test end to end — a browser that has
  never seen an API key signs in through a real OIDC exchange, with PKCE and state-forgery
  negative controls, against an issuer that runs in-process.
* Good, because one person can hold several sign-in methods and lose one without losing
  the account.
* Good, because no layer above `internal/auth` names an issuer, so a future provider
  cannot leak upward the way GitHub did.
* Bad, because refusing to merge on a conflict leaves a real duplicate-account case with
  no self-service fix: someone who signed in at two issuers before linking has two
  accounts, and only an administrator can reconcile them.
* Bad, because the provider key is permanent and unenforceably so — nothing stops an
  operator changing `OIDC_NAME`, and the failure presents as "everyone is suddenly a new
  user" rather than as an error.
* Bad, because trusting `sub` alone means an issuer that recycles subjects across deleted
  and recreated users would hand a new person an old account. No mainstream IdP does this,
  but OCIDex has no way to detect it.
* Bad, because there is no administrative view of identities: a user sees and manages only
  their own, and an administrator cannot answer "which issuer does this person use" from
  the UI.

### Confirmation

* `tests/oidc_integration_test.go` drives the whole flow against `internal/devidp`:
  six seeded personas sign in and come back as the right account with the right role, a
  previously unseen subject gets an account created, the authorize URL carries an S256
  `code_challenge`, and a code presented without the state cookie that began the flow is
  refused.
* `internal/api/authroutes_test.go` pins that the state cookie — not the callback URL —
  decides the provider, and that the PKCE verifier never appears in the redirect.
* `internal/api/identity_test.go` covers the link round trip end to end: a link lands on
  the account page, a cross-account subject produces the 409, a callback without a session
  is a 401, and unlinking the last identity is refused.
* `internal/devidp/devidp_test.go`'s `TestMockIDPShipsInNoImage` fails the build if the
  mock issuer is ever referenced by the production Dockerfile.
* `cmd/ocidex/main_test.go` covers the startup rule from both sides: GitHub-only,
  OIDC-only and both-configured all produce a working provider list, while a missing
  `SESSION_SECRET`, an empty provider list and a half-set GitHub credential pair each stop
  the process.
* `scripts/dev-auth.sh` blanks the GitHub credentials outright, so the local rig is a
  standing OIDC-only deployment: if the GitHub requirement ever comes back, the rig stops
  booting.
* `grep -r 'github_id\|github_username'` over `internal/`, `web/src/`, `db/queries/` and
  `pkg/` matches only two explanatory comments — no identifier, column or field. Outside
  `db/migrations/`, the words are history.

## Pros and Cons of the Options

### Generic OIDC behind a `Provider` interface

* Good, because one implementation covers Google, Okta, Entra, Keycloak, Auth0 and GitLab
  — every IdP a target deployment is likely to run.
* Good, because OIDC is conformance-tested and its discovery document means the endpoints,
  the JWKS and the supported response modes are read from the issuer rather than hardcoded
  per vendor.
* Good, because ID token claims are standardised, so `sub`, `email` and `name` mean the
  same thing at every issuer and there is one claims-mapping code path.
* Good, because the protocol is mockable in-process, which is what made the `/auth` routes
  testable at all.
* Bad, because it adds a runtime dependency on the issuer's discovery document being
  reachable at startup.
* Bad, because issuers vary in what they actually release — an issuer that withholds
  `email` and `name` yields an account with a bare subject for a display name.

### Hand-written adapters per provider

* Good, because each adapter can use the vendor's richest API, including non-standard
  extras like group membership or organisation checks.
* Good, because no discovery call is needed; endpoints are compiled in.
* Bad, because the cost is linear in issuers, and the second, third and fourth each cost
  roughly what GitHub cost — a fetch, a bespoke userinfo shape, a claims mapping and its
  own tests.
* Bad, because every adapter is a place for a subtly different security posture, and the
  weakest one sets the system's floor under Rule I2's threat model.
* Decisive, because the marginal cost of the *next* issuer is the number that matters, and
  it is a configuration block for generic OIDC versus a code change here.

### SAML 2.0

* Good, because it is what some enterprise IdPs are configured for first, and a few
  procurement processes still ask for it by name.
* Bad, because it roughly doubles the identity surface: XML metadata exchange, certificate
  rotation, signature and assertion validation, and canonicalisation — the last being a
  historically rich source of authentication bypasses that a small team is not well placed
  to get right.
* Bad, because it needs its own mock issuer to be testable, and the `internal/devidp`
  work would not carry over.
* Decisive, because the IdPs that speak SAML almost all also speak OIDC, so SAML buys
  little coverage for a large and dangerous increase in surface.

### An external identity broker in front of OCIDex

* Good, because it moves every protocol concern out of this codebase; OCIDex would trust a
  header or a single upstream OIDC issuer.
* Bad, because it makes a second service mandatory for any deployment that wants to sign
  in at all, including a laptop.
* Bad, because header-based trust is only as good as the network path, and OCIDex cannot
  verify from inside that the broker is the one setting the header.
* Note, because this option is not foreclosed: an operator who wants it can point
  `OIDC_ISSUER_URL` at Dex or Keycloak today. Rejecting it here means only that OCIDex does
  not *require* one.

## More Information

### Where the cost actually went

Worth recording, because the epic's scoping intuition was wrong in a useful way. The
protocol was the cheap half; decoupling from GitHub was the expense.

| Story | Change | Files |
|---|---|---|
| `.1` | `user_identity` table and backfill | 6 |
| `.2` | GitHub behind the `Provider` interface | 46 |
| `.3` | Generic OIDC provider with discovery and PKCE | 13 |
| `.4` | Mock OIDC issuer in the dev rig | 8 |
| `.5` | Multi-provider login UI, linking, column drop | 37 |

Story `.2` touched 46 files and added no capability whatsoever: it renamed the concept.
Story `.3` — the entire generic OIDC provider, the actual feature — touched 13. The
lesson is that the expensive part of adding a second implementation of anything is not the
second implementation, it is that the first one was allowed to name itself all the way up
the stack. `github_username` reached the sidebar because nothing stopped it.

### Related

* [ADR-046](0046-namespace-membership-rbac.md) — what an authenticated account may then
  do. Identity answers *who*; ADR-046 answers *what*. `ocidex_user.role` is the global
  axis referenced there.
* [docs/CONFIGURATION.md](../CONFIGURATION.md) — the `GITHUB_*` and `OIDC_*` variables.
* [docs/FRONTEND_DEV.md](../FRONTEND_DEV.md) — the dev-auth rig that runs the mock issuer.
* RFC 7636 (PKCE), and the OpenID Connect Discovery and Core specifications.
