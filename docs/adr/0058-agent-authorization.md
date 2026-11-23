---
status: "accepted"
date: 2026-11-22
decision-makers: Patrick Fenerty
---

# Agent authorization: scoped agent keys, server-held approvals, attributed actions

## Context and Problem Statement

`ocidex-mcp` (ADR-045) runs with the key `ocidex-cli login` saved: a personal key that, created
without a capability list, carries every capability (ADR-046 M5) across every namespace its holder
belongs to. That was acceptable while every MCP tool was a read. Agents now need to act (watch an
artifact, re-scan a registry, ingest the images a cluster runs with no SBOM), and three things are
missing before they can:

* **Scope.** A key can be narrowed by capability but not by namespace, so "this agent may re-scan
  the `acme` registry" cannot be said without also saying "and read and scan everything else I can".
* **Consent.** Nothing makes a person approve an agent's write. MCP's `destructiveHint` and
  elicitation depend on the client honouring them; a November 2026 measurement found 61% of
  server/host pairs enforce no approval by default, and that approval prompts are themselves
  attacked (fatigue, effect substitution).
* **Attribution.** `event.Actor` records "user". An action an agent took and an action its owner
  took are indistinguishable in the audit log.

How should OCIDex authorize an agent acting for a user, and where does that model live?

## Decision Drivers

* **Least privilege by default.** An agent never inherits its user's full rights; it gets what its
  task needs, for a bounded time.
* **One authorization model.** ADR-046 made the matrix code and probes every capability on every
  route at build time (`docs/AUTH_MATRIX.md` is a control, not a description). A second source of
  truth for permissions is how the two halves drift.
* **Approval the agent cannot forge or skip.** Enforced by the server; the human approves what will
  actually run, rendered by OCIDex, not text the agent wrote.
* **Attribution an operator can act on.** "Which agent, on whose behalf, through which tool."
* **Operational weight.** Self-hosted single-binary-per-role deployment (ADR-033); no new
  stateful service without a strong reason.
* **Standards at the edges.** Remote MCP will use OAuth 2.1 (sibling epic ocidex-1vom); the model
  here must map onto scoped, short-lived tokens without redesign.

## Considered Options

* **Extend ADR-046's native capability model** with key kind, namespace scope, presets, an
  approval-required set and quotas.
* **OpenFGA** (CNCF, ReBAC) as the decision service for agent and user authorization.
* **Cedar** (embedded via cedar-go) for agent policy, alongside the native model for users.
* **OPA/Rego** as a policy sidecar.

## Decision Outcome

Chosen option: **extend the native capability model**, because it meets every driver without a
second source of truth: namespace scope, presets, expiry and approvals are all expressible as
ceilings on the existing intersection, and the conformance harness keeps proving them. The
external engines solve a problem OCIDex does not yet have (arbitrary per-resource relationships),
at the price of the one property ADR-046 was built around.

The model is the following rules.

### A1. An agent key is a key kind, owned by a user

`api_key.kind` is `personal`, `agent` or `cluster` (cluster = today's `cluster_id`-bound push keys).
An agent key belongs to exactly one user and acts on their behalf; there is no free-standing agent
identity. A separate agent table was considered and rejected: an agent with no accountable human
is the thing to avoid, and owning the key keeps M5's "revoke the person, revoke their keys" for free.

`api_key.agent_label` is a free-text client name ("Claude Code on laptop") for display and audit.

### A2. Effective permission is a four-way intersection

For every capability check and every read:

> global role axis (M6) ∩ live namespace role (M2) ∩ key capability ceiling (M5) ∩ key namespace set

`api_key.namespace_ids` is the namespace set. Empty means "every namespace the holder belongs to"
and is allowed only on personal keys (today's behaviour, unchanged). Agent keys must name at least
one namespace.

The namespace set is applied where M5 applies the capability ceiling: in `can()`, **before**
`authz.Allow`, so an installation admin's scoped key is refused outside its namespaces exactly as
an admin's `{ingest}` key is refused `delete_namespace`.

It also narrows **reads**. Row visibility goes through the M4 SQL functions; they gain a key
namespace argument (a three-argument `visible_namespace_ids(viewer, admin, key_namespaces)` and the
same for `sbom_visible`/`artifact_visible`), and every query moves to the three-argument form. A
test fails the build if a query in `db/queries` still calls a two-argument form. Public namespaces
stay readable: the namespace set limits what a key may see *privately* and act on, not what is
public.

### A3. Presets are compile-time, beside `roleCaps`

Agent keys are created from a preset, defined in `internal/authz` and enumerated by the
conformance harness like roles:

| Preset | Capabilities | Approval required |
|---|---|---|
| `analyst` | `read_private` | none |
| `remediation` | `read_private` | none (self-scoped writes such as watch need no capability) |
| `coverage` | `read_private`, `trigger_scan` | `trigger_scan` |

Explicit capability lists remain possible for agent keys but go through the same validation.
Agent keys require an expiry: default 30 days, maximum 90. Personal keys are unchanged.

### A4. Approval is held by the server and bound to the effect

`api_key.approval_required` is a subset of the key's mutating capabilities. A request whose
capability check would pass but needs one of them is not executed: it is stored as a pending
action (method, route, body, the key, the target namespace) and answered `202 Accepted` with the
action's id and an **effect summary rendered by OCIDex** from the route and current state
("Re-scan registry ghcr-acme in namespace acme: 140 tags, uses its stored credentials").

* **Who approves.** A human in a browser session who themselves holds the capability in the target
  namespace now. Approving is never an escalation: you can only approve what you could do.
* **Sessions only.** Approve and deny are refused for every API key, personal included. The MCP
  server holds a key on disk; if any key could approve, the agent could approve itself.
* **Effect binding.** The approver sees the server-rendered summary and the stored request; on
  approval exactly that stored request executes, once, re-authorized at execution time (key
  unexpired and unrevoked, holder still allowed). Agent-supplied text is shown only as an
  untrusted "reason", never as the description of the effect.
* **Expiry.** Pending actions expire after 24 hours; an expired or denied action never executes.

### A5. Attribution follows on-behalf-of semantics

`event.Actor` gains the key id, key kind, agent label and the MCP tool name (sent by `ocidex-mcp`
in `X-OCIDex-Agent-Tool`, honoured only from agent keys). The audit record reads like RFC 8693's
`sub`/`act` pair: the subject is the user, the actor is the agent key. Approval events record the
approver separately from the requester.

### A6. Agent writes are budgeted

Each agent key has per-action-class budgets (scans per hour, images per ingest call), defaulted by
preset and capped installation-wide. Exceeding one is `429` with `Retry-After`. This bounds a
runaway or prompt-injected agent independently of approvals.

### A7. What agent keys may never do

Regardless of capabilities: manage keys (create, delete, list others'), approve or deny actions,
manage members, link identities, or use `installation_admin`. These stay session-only or
personal-key-only.

### A8. The MCP server earns its writes

`ocidex-mcp` registers write tools only when its key is an agent key whose effective permissions
allow them (read from a new `GET /api/v1/auth/keys/self`). A personal key keeps today's read-only
tool set and a startup notice pointing at `ocidex-cli mcp install`, which mints an agent key from a
preset. Data that came from SBOMs, advisories or registries is returned as clearly delimited,
sanitized data and the server instructions say it is untrusted.

### A9. No per-task grants in v1

OpenFGA's zero-standing pattern (a fresh narrow grant per task) is the strongest form of least
privilege, but expiry, namespace scope, presets, approvals and budgets together cover the risks
this epic targets, and per-task grants need a task boundary OCIDex cannot observe from a stdio
client. The remote-MCP epic's OAuth access tokens are short-lived, consented grants and are where
this gets revisited.

### Consequences

* Good, because the existing conformance harness proves the new ceilings route by route, the same
  way it proves roles.
* Good, because "agent did X for alice via tool Y, approved by bob" is one audit row.
* Good, because a stolen agent key is bounded by namespace, preset, expiry and budget, and cannot
  approve its own writes.
* Bad, because every read query changes signature (A2). It is mechanical but wide, and the
  two-argument guard has to land with it.
* Bad, because approvals add a stateful workflow (pending actions, expiry job, UI inbox) the
  product did not have.
* Bad, because "may scan only registry X" is still not expressible; the unit is the namespace.
  If that becomes a requirement, Cedar is the first option to revisit.

### Confirmation

* The AUTH_MATRIX conformance harness gains namespace-scoped and preset keys and probes every
  route with them; approval/deny operations are asserted session-only.
* A test fails if any `db/queries` file calls a two-argument visibility function.
* Integration tests: a key scoped to namespace A gets 404 on B's private artifact and 403 on
  `trigger_scan` in B; an approval-required scan returns 202, executes once on approval, never on
  deny or expiry, and is refused when approved by an API key.
* `ocidex-mcp` tests: no write tool is registered for a personal key or an `analyst` preset.

## Pros and Cons of the Options

### Extend the native capability model

* Good, because one model, already exhaustive and build-time tested (ADR-046 M3).
* Good, because no new service; decisions stay in-process and in SQL where row filtering already is.
* Good, because the intersection in M5 already gives "never stronger than the holder".
* Bad, because resource-level rules finer than a namespace need new code each time.

### OpenFGA

* Good, because ReBAC handles arbitrary relationships and has documented agent patterns
  (task grants with expiry, turn limits, agent binding).
* Good, because it is a CNCF project with SDKs and tooling.
* Bad, because it is a second source of truth: roles and visibility would live in OCIDex's matrix
  and SQL functions *and* in an FGA model, or all row filtering would have to move to list-objects
  calls, which the M4 measurements argue against.
* Bad, because a new stateful service to deploy, back up and keep consistent for every install.

### Cedar (embedded)

* Good, because embeddable (no service), analyzable, and well suited to per-tool, per-resource
  agent policy.
* Bad, because two policy languages for one system: users in Go, agents in Cedar, with the
  intersection between them hand-maintained.
* Neutral, because it is the right tool the day per-resource agent rules are needed (see Bad above).

### OPA/Rego

* Good, because flexible and widely deployed for infrastructure policy.
* Bad, because a sidecar per API replica and a policy language suited to infrastructure admission
  rather than application authorization; the same second-source-of-truth problem as OpenFGA.

## More Information

* Implements the scope decision deferred in ocidex-vt62; stories are the children of ocidex-m3yx.
  Remote MCP over OAuth 2.1 (ocidex-1vom) builds on A1–A6.
* ADR-045 (MCP server) is amended by A8; ADR-046 (membership RBAC) by A2–A3 and A7.
* MCP authorization specification, revision 2026-07-28 (OAuth 2.1, RFC 9728, RFC 8707).
* OpenFGA, "Authorization for Agents" (task-based, zero-standing grants).
* "When Neither Side Confirms: Destructive Tool Approval Across MCP Servers and Hosts",
  arXiv 2611.02527; "Approve What, Exactly? Effect Binding and Trusted Rendering for Agent Step-Up
  Authorization", arXiv 2610.21063; "Loopjacking", arXiv 2609.21081.
* RFC 8693 (token exchange: `sub`/`act` on-behalf-of semantics).
