# ADR-029: CLI Tool Design

**Status:** Accepted  
**Date:** 2026-08-02  
**Epic:** ocidex-e3g — 1.2 CLI tool

---

## Context

OCIDex needs a command-line client so that CI systems and operators can drive the API
without a browser. `pkg/client` (ADR-028) already provides the typed Go surface; this ADR
decides what the binary wrapped around it looks like.

The CLI is not greenfield. Epic `ocidex-0gp` shipped a deliberately minimal slice —
`cmd/ocidex-cli/{main.go,sbom.go}`, a Cobra root and one working `sbom push` command — so
that the Tekton `sbom-push` task could dogfood the upload path. That slice made three
decisions in passing (binary name, server flag, credential source) and left the rest
open. This ADR ratifies or overturns each, rather than pretending the surface is empty:
`.tektonic/jobs/sbom-push/` is a live consumer, and any decision here that contradicts it
costs a CI change.

## Decision

### Binary name: `ocidex-cli`

`cmd/ocidex/` is the API server, and both binaries ship from the same module and the same
`docker/Dockerfile`. `ocidex` is therefore taken; a CLI named `ocidex` would collide on
`go build ./cmd/...`, in `$GOPATH/bin`, and in any image carrying both.

The alternative — rename the server to `ocidex-server` and free up `ocidex` for the CLI —
was rejected as churn: the server name appears in the Helm chart, the operator's pod
specs, nine Dockerfile stages, and the `sbom-push` binary list. The CLI is the newer,
lower-traffic name and should absorb the suffix.

### Command grammar: noun → verb

```
ocidex-cli <noun> <verb> [args] [flags]

ocidex-cli registry list
ocidex-cli sbom push ./ocidex.cdx.json --source ocidex/ci
ocidex-cli artifact changelog <id>
```

Nouns mirror the API's resource nouns and the method groupings already present in
`pkg/client/client.go` (`registry`, `namespace`, `source`, `sbom`, `artifact`,
`component`, `job`, `key`). One noun package per file under `cmd/ocidex-cli/`, each
exporting a single `new<Noun>Cmd(*rootConfig) *cobra.Command`, so the command tree mirrors
the client interface and a new API resource has one obvious home.

Verb → noun (`ocidex-cli list registries`) was rejected: it puts the least
discriminating word first, so tab-completion and `--help` are least useful exactly where
discovery matters.

### Server address: `--server`, env `OCIDEX_URL`

Persistent flag on the root command. Resolution order: `--server` flag, then
`OCIDEX_URL`, then the config file's `server` key, then `http://localhost:8080`.

The story that produced this ADR specified `OCIDEX_SERVER`. **Rejected.** The shipped
slice reads `OCIDEX_URL`, and `.tektonic/jobs/sbom-push/spec.ts` sets `OCIDEX_URL` in the
push step's environment. Renaming buys nothing and breaks a working pipeline; `_URL` is
also the more accurate name, since the value is a base URL and not a host.

### Authentication: `OCIDEX_API_KEY`, then config file. No flag.

Resolution order: `OCIDEX_API_KEY`, then the config file's `api-key` key. Commands that
need a key and find none fail with a message naming both sources.

The story specified `--api-key` as the highest-precedence source. **Rejected.** A
credential passed as an argument is visible in the process table to every user on the
host, lands in shell history, and is echoed by any CI runner that prints the commands it
executes — including Tekton, which logs each step's script. The env var is the standard
way CI injects a secret and the way the `sbom-push` task already does it
(`secretKeyRef` → `OCIDEX_API_KEY`). Omitting the flag costs nothing that the env var and
the config file do not cover.

`--api-key-file` was considered as a middle ground for scripts that hold the key in a
file. Deferred, not rejected: the config file covers the same case today, and the flag
can be added later without changing the resolution order above.

### Config file: `~/.config/ocidex/config.yaml`

Honours `$XDG_CONFIG_HOME` when set; falls back to `~/.config`. Absent file is not an
error — every key it holds has an env var or a default.

```yaml
server: https://ocidex.example.com
api-key: ocidex_pat_...
output: table
```

The file is read only if its mode has no group or world bits set when it contains
`api-key`; otherwise the CLI errors rather than silently using a world-readable
credential, matching `ssh`'s handling of private keys. There is no `--config` flag and no
config-file search up the directory tree: a per-repo config file that silently changes
which server a command talks to is a footgun in a tool whose verbs include `delete`.

### Output: `--output` / `-o`, one of `table|json|yaml`, default `table`

- **table** — human-readable, column-aligned, for terminals.
- **json** — the API's own response shape, unmodified. Not a bespoke CLI schema: the
  OpenAPI spec already documents these types, and `pkg/client` already carries them, so
  there is exactly one thing to keep in sync.
- **yaml** — the same structure, YAML-encoded, for pasting into manifests.

Rendered output goes to stdout; progress, warnings, and errors go to stderr, so
`ocidex-cli sbom list -o json | jq` works unconditionally. A shared renderer package
(`ocidex-e3g.3`) owns the three encoders; subcommands hand it a value and a column
definition and never format anything themselves.

### Exit codes

The shipped slice exits 1 for every failure. That is retrofitted to:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | API or runtime failure |
| 2 | usage error (bad flags, wrong arity) |
| 3 | not found (`client.ErrNotFound`) |
| 4 | forbidden (`client.ErrForbidden`) |

3 and 4 exist because the typed sentinels in `pkg/client/errors.go` make them free, and
because "absent" versus "not allowed to see" is the distinction a script most often needs
to branch on. No further codes: anything more granular belongs in the stderr message.

### Client construction

One `client.New(client.Config{BaseURL, APIKey})` per invocation, built from the resolved
configuration in a root `PersistentPreRunE`. Subcommands receive the `client.Client`
*interface*, never the concrete `httpClient`, so `FakeClient` (ADR-028) drives command
tests without an HTTP server.

## Consequences

- `cmd/ocidex-cli/main.go` gains a config-file loader, an output flag, and the exit-code
  mapping; `serverConfig` becomes the fuller `rootConfig`. `sbom push` keeps its existing
  flags and behaviour — the retrofit is additive, and the `sbom-push` Tekton task needs
  no change.
- `sbom push` is the one command whose subject flags are not derived from a `pkg/client`
  method signature (see ADR-040); it stays hand-rolled.
- The credential decision means there is no way to pass a key inline. This is intentional
  and will look like a missing feature until someone reads this section.
- Every new API resource implies a new noun file; the command tree is expected to grow to
  match `Client`, not to curate a subset of it.

## More Information

- ADR-028 — the `pkg/client` interface, error sentinels, and `FakeClient` this CLI is
  built on.
- ADR-040 — caller-declared subject identity, which is why `sbom push` has explicit
  `--subject-*` flags.
- `.tektonic/jobs/sbom-push/` — the CLI's first and currently only automated consumer.
