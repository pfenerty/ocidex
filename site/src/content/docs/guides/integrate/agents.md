---
title: Agents
description: Give an AI agent its own limited key, approve what it asks to change, and see what it did.
sidebar:
  order: 5
---

An agent such as Claude Code or Cursor talks to OCIDex through [`ocidex-mcp`](/guides/integrate/mcp/).
Give it an **agent key**: a key that belongs to you but is limited to a preset, to the namespaces
you choose and to a set lifetime, and whose writes can wait for your approval. Why this is safe
enough to let an agent act is on [Agent security](/concepts/agent-security/).

## Connect an agent

From a terminal signed in with `ocidex-cli login`:

```sh
ocidex-cli mcp install --client claude-code --namespace acme --preset coverage
```

This creates the key and writes it into the client's config (`--client claude-desktop` or
`cursor` for those). The key is never printed. Restart the client and ask it to call
`ocidex_whoami`, which reports what the key may do.

Or, in the web UI, open **Admin → Agents**, fill in **Create an agent key** and copy the
`claude mcp add ...` command shown once after creating it.

## Choose what it may do

| Preset | Reads | May change | Held for your approval |
|---|---|---|---|
| `analyst` | everything in its namespaces, private data included | nothing | - |
| `remediation` | as analyst | your watchlist | - |
| `coverage` | as analyst | asks for registry scans and scans of images a cluster runs with no SBOM | every scan |

The key also needs:

- **Namespaces.** At least one. It sees private data and acts only there; public data elsewhere
  stays readable.
- **An expiry.** 30 days by default, 90 at most. Create a new key when it runs out.
- **A client label** (optional), such as "Claude Code on laptop". It appears on approvals and in
  the audit log.

An agent key can never manage keys (its own included), approve requests, manage members, delete a
namespace or use installation admin rights, whatever you give it.

## Approve what it asks to change

When an agent asks for a change its key holds for approval, nothing runs. OCIDex stores the request,
the agent gets back a link, and the request waits in **Admin → Agents → Waiting for your approval**.

Open it to see:

- **what will happen**, written by OCIDex from the request, not by the agent;
- the exact request that will run;
- the agent's own note, marked as unverified.

**Approve and run** runs exactly that stored request, once, as the agent's key. That happens only
if the key is still valid and you can still make the change yourself. **Deny** discards it.
Requests expire after 24 hours.

Only someone signed in to the web UI can approve or deny, and only if they could make the change
themselves. No key can, so an agent cannot approve its own request. From a terminal,
`ocidex-cli approval list` shows what is waiting and `ocidex-cli approval open <id>` opens it in the
browser.

If your MCP client supports confirmation prompts (elicitation), changes that are not held are also
shown to you in the client before they are sent.

## Budgets

Each agent key may make at most 120 changes and 20 scan requests an hour by default, counted when
asked, so asking repeatedly for approval counts too. Past that, requests are refused until the next
hour. A key can be created with a lower or higher budget, up to 1,000 changes and 200 scans an hour
(`scansPerHour` / `writesPerHour` when creating it through the API). An agent's request to scan a
cluster's unknown images must name the images, at most 200 at a time.

## See what it did, and revoke it

**Admin → Agents** lists your agent keys with their namespaces, what they may do, expiry and last
use. **Activity** shows every change a key made, asked for or was refused, with the MCP tool that
made it. The audit log records agent actions as yours, made through that key and tool, and records
who approved a held request separately from who asked.

**Revoke** stops the key at once. Requests it asked for can no longer run.
