---
title: MCP server
description: Let an AI agent query your SBOMs, diffs and vulnerabilities through the Model Context Protocol.
sidebar:
  order: 4
---

`ocidex-mcp` serves the OCIDex catalog to AI agents over the [Model Context
Protocol](https://modelcontextprotocol.io). It is a local server: your MCP client starts it as a
child process and talks to it over stdin and stdout, so there's nothing to deploy. It calls the
OCIDex API with your key.

Ask your agent things like "which of our images have CVE-2024-3094?", "what changed between the
last two releases of acme/api?" or "where do we ship GPL-licensed code?".

## Set up

1. **Install it**:

   ```sh
   go install github.com/pfenerty/ocidex/cmd/ocidex-mcp@latest
   ```

2. **Give it a key.** It reads the same credentials as `ocidex-cli`, so:

   ```sh
   ocidex-cli login          # writes ~/.config/ocidex/config.yaml
   ```

   Every tool except ingest works with a read-only key. Ingesting needs the `ingest` capability.
   There's deliberately no key flag: use the config file or `OCIDEX_API_KEY`.

3. **Register it with your client.** For Claude Code:

   ```sh
   claude mcp add ocidex -- ocidex-mcp
   claude mcp add ocidex -- ocidex-mcp --server https://ocidex.example.com   # a specific server
   ```

   For a client configured with JSON:

   ```json
   {
     "mcpServers": {
       "ocidex": {
         "command": "ocidex-mcp",
         "env": { "OCIDEX_URL": "https://ocidex.example.com" }
       }
     }
   }
   ```

4. **Check it**: ask the agent to call `ocidex_whoami`. It reports the server and the user the key
   belongs to.

The server is resolved like the CLI's: `--server`, then `OCIDEX_URL`, then the config file.

## Tools

| Tool | What it does |
| --- | --- |
| `ocidex_whoami` | Which server, user and role. Also the connection check. |
| `ocidex_lookup_artifact` | Find an artifact by name, narrowed by `type` and `group`. |
| `ocidex_get_artifact` | Fetch an artifact by id. |
| `ocidex_lookup_sbom` | Find an SBOM by digest, or by artifact and version (and architecture, flavor). |
| `ocidex_lookup_license` | Find a license by SPDX id. |
| `ocidex_search_components` | Search component occurrences by name or purl. |
| `ocidex_list_namespaces` | The namespaces the key can see. |
| `ocidex_diff_sboms` | What changed between two SBOMs. |
| `ocidex_diff_tree` | One level of the dependency tree diff, most-changed first. |
| `ocidex_artifact_changelog` | An artifact's version-to-version history. |
| `ocidex_artifact_vulnerabilities` | An artifact's vulnerabilities by severity. |
| `ocidex_component_vulnerabilities` | The advisories affecting one component. |
| `ocidex_get_vulnerability` | An advisory, and the artifacts it affects. |
| `ocidex_ingest_sbom` | Upload a CycloneDX document. Needs `ingest`. |

When a name matches several artifacts, a lookup returns the candidates and what tells them apart,
rather than guessing, so the agent can ask again more precisely.

The server also offers the API's OpenAPI document as the resource `ocidex://openapi.json`, fetched
from the running server, for anything the tools don't cover.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The server exits at once, saying `no API key` | No credentials in the config file or the environment | `ocidex-cli login`, or set `OCIDEX_API_KEY` |
| The server exits, mentioning `chmod 600` | The config file is readable by others | `chmod 600 ~/.config/ocidex/config.yaml` |
| Every tool says "not found" | The key sees no namespaces, or the artifacts are private | Check `ocidex_whoami` and `ocidex_list_namespaces` |
| Ingest says the key can't write | The key lacks `ingest`, or its owner's role doesn't allow it | Create a key with `--capability ingest` and log in again |
| The client reports a protocol error | Something wrote to stdout | Only the protocol may use stdout. Suspect a wrapper script. |

The server writes its own diagnostics to stderr, which appear in your client's server log, not in
the conversation.
