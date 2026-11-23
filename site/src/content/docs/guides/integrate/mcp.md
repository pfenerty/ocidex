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
last two releases of acme/api?", "where do we ship GPL-licensed code?" or "plan remediation for
what the homelab cluster is running".

## Set up

1. **Install it**:

   ```sh
   go install github.com/pfenerty/ocidex/cmd/ocidex-mcp@latest
   ```

2. **Register it with an agent key** (recommended). Signed in with `ocidex-cli login`, run:

   ```sh
   ocidex-cli mcp install --client claude-code --namespace acme --preset analyst
   ```

   This creates an agent key limited to the namespaces you name and expiring in 30 days, and writes
   it into the client's user-wide config (`--client claude-desktop` or `cursor` for those). The key
   is never printed, and running the command again changes nothing (`--rotate` replaces the key).
   Presets: `analyst` reads, `remediation` also manages your watchlist, and `coverage` may also ask
   for scans, each one held for your approval. Only agent keys get the write tools below. Restart
   the client, then skip to step 4.

   **Or give it your personal key**, read-only. It reads the same credentials as `ocidex-cli`, so:

   ```sh
   ocidex-cli login          # writes ~/.config/ocidex/config.yaml
   ```

   Every tool except ingest works with a read-only key. Ingesting needs the `ingest` capability.
   There's deliberately no key flag: use the config file or `OCIDEX_API_KEY`.

3. **Register it with your client** (personal-key setup only). For Claude Code:

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
| `ocidex_artifact_vulnerabilities` | Severity counts for an artifact's latest version. |
| `ocidex_artifact_findings` | An artifact's advisories across its recent versions. |
| `ocidex_sbom_findings` | One SBOM's advisories with fixed versions and fix state, by advisory or by package. |
| `ocidex_list_artifact_versions` | An artifact's versions, newest first, with SBOM ids and severity counts. |
| `ocidex_list_sbom_components` | The components in one SBOM, optionally only vulnerable or direct ones. |
| `ocidex_artifact_lineage` | The base image an artifact is built on, and what is built on it. |
| `ocidex_component_versions` | Every version of a component across the catalog, and where each ships. |
| `ocidex_component_vulnerabilities` | The advisories affecting one component. |
| `ocidex_get_vulnerability` | An advisory, and the artifacts it affects. |
| `ocidex_top_vulnerabilities` | Advisories ranked across the catalog, or across your own namespaces. |
| `ocidex_search_artifacts` | Artifacts whose name contains some text. |
| `ocidex_artifact_license_summary` | License counts for an artifact's latest SBOM. |
| `ocidex_sbom_drift` | Changes to an SBOM's signing or provenance status. |
| `ocidex_data_freshness` | Whether vulnerability matching has caught up with every SBOM. |
| `ocidex_list_clusters` | Clusters, with health, running criticals and SBOM coverage. |
| `ocidex_cluster_vulnerabilities` | Advisories in running images, by severity or workloads exposed. |
| `ocidex_cluster_images` | Running images, most vulnerable first, with their SBOM ids. |
| `ocidex_cluster_workloads` | Running workloads, most vulnerable first. |
| `ocidex_cluster_coverage_gaps` | Running images with no SBOM, and what would close each gap. |
| `ocidex_vulnerability_workloads` | Workloads running an image that carries one advisory. |
| `ocidex_ingest_sbom` | Upload a CycloneDX document. Needs `ingest`. |

### Write tools

Only an agent key gets these (see [Agents](/guides/integrate/agents/)). Each one is listed only when the
key may use it, takes `preview: true` to describe the request without sending it, and is safe to
retry.

| Tool | What it does | Needs |
| --- | --- | --- |
| `ocidex_watch_artifact` / `ocidex_unwatch_artifact` | Add an artifact to the user's watchlist, or remove it. | nothing beyond the key |
| `ocidex_scan_registry` | Queue scans of a registry's new and changed images. | `trigger_scan` |
| `ocidex_ingest_unknown_images` | Queue scans of named images a cluster runs with no SBOM (at most 200 per call). | `trigger_scan` |
| `ocidex_approval_status` | Whether a held request was approved, and what happened when it ran. | nothing beyond the key |

A write the key must have approved comes back `held`, with OCIDex's own description of the effect
and an `approval_url`. Nothing runs until a person approves it in the browser. The agent is told to
pass on the link and poll `ocidex_approval_status`, not to resend. Agent keys also have hourly
budgets; a spent budget is refused until the next hour.

If your client supports MCP elicitation, a write that would run straight away is first shown to you
with a request to allow it. Declining sends nothing. Held writes skip that prompt, since you approve
them in OCIDex instead. Clients without elicitation run the write without asking, within the key's
limits.

When a name matches several artifacts, a lookup returns the candidates and what tells them apart,
rather than guessing, so the agent can ask again more precisely.

Cluster tools take a cluster's name or id. A name shared by clusters in different namespaces
returns the candidates, like the lookups do.

## Prompts

Clients that support MCP prompts (Claude Code shows them as slash commands) get two workflows:

| Prompt | Arguments | What it produces |
| --- | --- | --- |
| `remediate_image` | `image`, optional `version` | A remediation plan for one image |
| `remediate_cluster` | `cluster`, optional `k8s_namespace` | A remediation plan for what a cluster runs |

Both group the plan by action: redeploy a newer version, rebuild on a current base image, upgrade
packages (installed version to fixed version), accept or mitigate what has no fix, and list what
nobody can assess yet. Without prompt support, ask in plain words; the server's instructions teach
the same tool sequence.

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
