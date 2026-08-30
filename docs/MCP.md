# MCP Server

`ocidex-mcp` serves the OCIDex catalog to agents over the [Model Context
Protocol](https://modelcontextprotocol.io). It is a local stdio server: the MCP client launches
the binary as a child process and talks JSON-RPC to it on stdin/stdout, so there is nothing to
deploy and no second network hop. The reasoning — and why this is not an endpoint on the API
service — is in [ADR-045](adr/0045-mcp-server.md).

## Prerequisites

An API key. `ocidex-mcp` reads the same credentials `ocidex-cli` writes, so provisioning it is
one command:

```sh
ocidex-cli login          # writes ~/.config/ocidex/config.yaml, mode 0600
```

The key needs the `ingest` capability only for `ocidex_ingest_sbom`; every other tool is
satisfied by a `read_private` key, and a key without `ingest` makes the ingest tool fail with a
message that says so. Capabilities are a ceiling — the key can never exceed what its owner's
namespace roles allow, so a demotion narrows it with no key change (ADR-046).

There is deliberately **no `--key` flag**: an argument is visible in the process table and
echoed by any CI runner that logs its commands. The two supported paths are the config file and
`OCIDEX_API_KEY`. A config file readable by anyone but its owner is refused rather than used —
`chmod 600 ~/.config/ocidex/config.yaml` if you see that error.

Without a key the server exits at startup with code 2 instead of connecting and failing every
tool call, because a server that answers "error" to everything reads to a model as an empty
catalog rather than as a misconfiguration.

## Install

```sh
# With a Go toolchain
go install github.com/pfenerty/ocidex/cmd/ocidex-mcp@latest

# From a checkout
make build     # produces bin/ocidex-mcp alongside bin/ocidex-cli
```

## Register with a client

```sh
claude mcp add ocidex -- ocidex-mcp
```

Point it at a specific server with either the flag or the environment:

```sh
claude mcp add ocidex --env OCIDEX_URL=https://ocidex.example -- ocidex-mcp
claude mcp add ocidex -- ocidex-mcp --server https://ocidex.example
```

Precedence is the CLI's: `--server` beats `OCIDEX_URL`, which beats the `server` key in the
config file. For clients configured by JSON rather than a command, the equivalent entry is:

```json
{
  "mcpServers": {
    "ocidex": {
      "command": "ocidex-mcp",
      "env": { "OCIDEX_URL": "https://ocidex.example" }
    }
  }
}
```

Confirm the connection by asking the agent to call `ocidex_whoami` — the cheapest authenticated
call in the API, which reports the server URL and the user the key belongs to.

## Tools

| Tool | Purpose |
|------|---------|
| `ocidex_whoami` | Which server, which user, which role — also the connectivity check |
| `ocidex_lookup_artifact` | Resolve an artifact by name, narrowing with `type` and `group` |
| `ocidex_get_artifact` | Fetch an artifact by UUID |
| `ocidex_lookup_sbom` | Resolve an SBOM by `digest`, or by `artifact` + `version` (+ `arch`, `flavor`) |
| `ocidex_lookup_license` | Resolve a license by SPDX id |
| `ocidex_search_components` | Search component occurrences by `name` or `purl` |
| `ocidex_list_namespaces` | Namespaces the key can see |
| `ocidex_diff_sboms` | Component-level changes between two SBOMs, paged and filterable by direction |
| `ocidex_diff_tree` | One level of the dependency tree, ordered by descendant change count |
| `ocidex_artifact_changelog` | Version-to-version history for an artifact |
| `ocidex_artifact_vulnerabilities` | Severity histogram for an artifact |
| `ocidex_component_vulnerabilities` | Advisories hitting one component occurrence |
| `ocidex_get_vulnerability` | An advisory and the artifacts it affects |
| `ocidex_ingest_sbom` | Upload a CycloneDX document (**write**; needs `ingest`) |

Name-keyed lookups follow the [ADR-042](adr/0042-canonical-resource-urls.md) qualifier ladder:
a name that matches several artifacts returns the candidate list with the qualifier that
separates them, rather than picking one. The tools surface that list verbatim so the agent can
retry with `type` or `group` instead of guessing.

Ingesting a **container** SBOM requires `version`, `architecture` and `build_date` unless the
document already carries them; the API rejects the upload otherwise.

## Resources

`ocidex://openapi.json` is the OpenAPI 3.1 description of the API, fetched from the running
server rather than embedded in the binary — a binary built from one revision and pointed at a
server running another would otherwise hand out a spec that disagrees with every response. Read
it when an endpoint is not covered by a tool; prefer the tools otherwise, since they handle
pagination and ambiguous lookups.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Server exits immediately, log says `no API key` | No credentials in the config file or environment | `ocidex-cli login`, or set `OCIDEX_API_KEY` |
| Server exits, log mentions `chmod 600` | Config file is group- or world-readable | `chmod 600 ~/.config/ocidex/config.yaml` |
| Every tool returns "not found" | The key's namespaces are empty, or the artifacts are private to someone else | Check `ocidex_whoami` and `ocidex_list_namespaces` |
| `ocidex_ingest_sbom` says the key cannot write | The key lacks `ingest`, or its owner's role on the namespace does not grant it | Create a key with `--capability ingest` and re-run `ocidex-cli login`, or have the namespace owner raise your role |
| Client reports a protocol/parse error | Something wrote to stdout | Only JSON-RPC may go to stdout; the server keeps all diagnostics on stderr, so suspect a wrapper script |

Startup diagnostics — version, target server — go to stderr and appear in the client's server
log, not in the conversation.
