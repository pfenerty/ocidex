---
status: "accepted"
date: 2026-08-17
decision-makers: Patrick Fenerty
---

# MCP server as a standalone binary over the generated client SDK

## Context and Problem Statement

An agent that wants to answer "which of our images ship log4j 2.14" currently has to
hand-roll HTTP against the OCIDex API: read the OpenAPI spec, construct URLs, paginate,
and interpret status codes. Every agent redoes that work, and each one gets the
ADR-042 lookup semantics subtly wrong in its own way — a 409 with a candidate list is
useless to a caller that treats every non-2xx as a failure.

The Model Context Protocol is the interoperable way to hand a model a typed tool
surface. The question is where that surface lives: inside the existing API service, or
in a binary of its own; and how it authenticates, given the CLI already has a working
credential story.

## Decision Drivers

* **No second credential store.** `ocidex-cli login` already writes a mode-0600 key to
  `~/.config/ocidex/config.yaml` and verifies it against the server. A second store means
  a second thing to rotate and a second thing to leak.
* **Tool schemas must not drift from the API.** A hand-written schema that lags an API
  change produces a tool that fails at call time, which a model interprets as an empty
  catalog rather than as a bug.
* **No new transport surface on the server.** The API is deployed behind a Gateway with
  an auth model per ADR-025; adding a long-lived streaming endpoint to it widens the
  attack surface and the operational burden for a feature only local agents use.
* **Errors must be actionable by a model, not just by a human.** The model reads the
  error string and decides what to do next.
* **Dependency footprint.** ADR-037 already cost 786 transitive dependencies; another
  such addition needs justification.

## Considered Options

* Standalone `cmd/ocidex-mcp` stdio binary wrapping `pkg/client`
* An MCP endpoint (HTTP+SSE / streamable HTTP) served by the existing API service
* No MCP server; publish the OpenAPI spec and let each agent generate its own client

## Decision Outcome

Chosen option: **standalone `cmd/ocidex-mcp` stdio binary wrapping `pkg/client`**,
because it is the only option that gets tool schemas for free from a drift-guarded
source, needs no change to the deployed service, and inherits the CLI's credentials
rather than inventing a parallel path.

Specifically:

**S1. Transport is stdio only.** The client launches the binary as a subprocess
(`claude mcp add ocidex -- ocidex-mcp`), so the process boundary *is* the trust
boundary — the server runs as the user, with the user's key, and is reachable by nothing
else. Nothing but JSON-RPC may be written to stdout; every log line and diagnostic goes
to stderr, which MCP clients surface as server output.

**S2. The SDK is `github.com/modelcontextprotocol/go-sdk`, pinned at v1.7.0.** It is the
specification's own Go implementation, it is past 1.0 so the API is stable, and it costs
four transitive dependencies (`jsonschema-go`, `uritemplate`, `segmentio/encoding`,
`segmentio/asm`). Its generic `AddTool` derives each tool's input and output schema from
Go types and validates arguments before the handler runs, which is what keeps the
schemas honest.

**S3. Tools call `pkg/client`, never the HTTP API directly.** `pkg/client` is
oapi-codegen output from the OpenAPI spec and is drift-guarded by `make check`
(`generate-client-check`), so an API change that would break a tool fails CI at the
source. The `client.Client` interface is what tool handlers take, so `FakeClient` is a
drop-in for tests and no test needs a live server.

**S4. Credentials come from `internal/cliconfig`, shared with ocidex-cli.** The file
format, the XDG path, the mode-0600 refusal and the flag → env → file → default
precedence have one implementation, used by both binaries. `ocidex-cli login` therefore
provisions the MCP server as a side effect, and `logout` de-provisions it. There is
deliberately no `--key` flag: an argument is visible in the process table.

**S5. A missing key is a startup failure, not a per-call failure.** Exit code 2, with a
message naming both `OCIDEX_API_KEY` and the config path. A server that connects cleanly
and then fails every tool reads to a model as a catalog with nothing in it.

**S6. API errors become tool errors with advice attached.** The SDK routes a handler's
returned error into `CallToolResult.IsError`, so the channel is settled; what this ADR
fixes is the wording. `toolError` maps each of `pkg/client`'s typed errors to a message
that says what happened *and* what would work instead — a 404 notes that invisibility is
indistinguishable from absence, a 403 names the scope required, a 401 says to re-run
`ocidex-cli login`, and an ADR-042 `ConflictError` renders its candidate list with
sorted qualifiers so the model can retry one rung down the qualifier ladder. Every
mapping wraps with `%w`, so `errors.Is`/`errors.As` still work above it.

**S7. Tool names are prefixed `ocidex_`.** A client with several servers connected shows
a flat tool list; a bare `whoami` there is ambiguous.

### Consequences

* Good, because the tool surface tracks the API automatically: change a handler type,
  run `make openapi` and `make generate-client`, and the tool schema follows.
* Good, because there is exactly one credential store and one permission check.
* Good, because the server is unreachable over the network by construction — no port, no
  listener, no new authentication path in the deployed service.
* Good, because every tool is testable against `FakeClient` over the SDK's in-memory
  transport, which exercises the real handshake and schema validation.
* Bad, because each agent needs the binary installed locally; there is no hosted
  multi-tenant MCP endpoint. Remote access remains the HTTP API's job.
* Bad, because the stdio server holds one key for one user, so it cannot serve an agent
  acting on behalf of several users. That is the right default for a local agent and the
  wrong one for a shared service; revisit only with a concrete multi-tenant requirement.
* Neutral, because tool coverage is now a maintenance surface of its own: an API endpoint
  with no tool is invisible to agents even though the SDK exposes it.

### Confirmation

`make build` produces `bin/ocidex-mcp`; `make check` runs the package's tests, which
connect a real MCP client to the server over `mcp.NewInMemoryTransports`, assert the
handshake, list tools, and call them against `FakeClient`. Credential reuse is covered by
tests that write a config file the way `ocidex-cli login` does and assert the server
resolves it — including the world-readable-key refusal.

## Pros and Cons of the Options

### Standalone stdio binary wrapping pkg/client

* Good, because schemas derive from the drift-guarded generated client.
* Good, because it reuses the CLI's credentials and needs no server change.
* Good, because the process boundary is the trust boundary.
* Bad, because it must be installed on each machine that runs an agent.

### MCP endpoint on the existing API service

* Good, because nothing to install; any agent with a URL and a key can connect.
* Bad, because it adds a long-lived streaming transport, session state, and a second
  authentication path to the service that holds the data.
* Bad, because MCP sessions are stateful in a way the current stateless HTTP deployment
  is not, which complicates horizontal scaling and rollout.
* Bad, because it couples the protocol's release cadence to the API service's.

### No MCP server; publish the spec

* Good, because zero maintenance.
* Bad, because every agent re-implements pagination, visibility semantics, and the
  ADR-042 qualifier ladder — and gets the 409 handling wrong, which is the exact failure
  this epic exists to remove.

## More Information

* ADR-029 records the CLI design whose credential handling this shares.
* ADR-042 defines the name-keyed resolvers and the 409-with-candidates contract that the
  lookup tools surface.
* ADR-025 defines the visibility model that bounds every tool's results: an empty result
  means "nothing visible to this key", not "nothing exists".
