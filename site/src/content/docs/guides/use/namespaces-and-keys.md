---
title: Namespaces and keys
description: Create namespaces, manage their members, and create API keys.
sidebar:
  order: 8
---

How namespaces, roles and keys fit together is in [Namespaces and
access](/concepts/namespaces-and-access/). This page is how to manage them.

## Namespaces

A namespace is created along with its first registry (leave **Namespace** empty in the registry
form), or on its own with `ocidex-cli namespace create`. Whoever creates it is its owner. An
operator can restrict creating namespaces to members and admins.

Installation admins manage every namespace under **Admin → Namespaces**: visibility, members and
roles.

### Members

Each member has one role: **owner**, **maintainer**, **security**, **developer** or **viewer**.
Only an owner (or an admin) can add or remove members and change roles, and each namespace has
exactly one owner.

:::note
In this release the **Namespaces** tab is shown only to installation admins. A namespace owner
manages members through the API:

```sh
# Add someone, or change their role
curl -X PUT "https://ocidex.example.com/api/v1/namespaces/<namespace id>/members/<user id>" \
  -H "Authorization: Bearer $OCIDEX_API_KEY" -H "Content-Type: application/json" \
  -d '{"role":"developer"}'

# Remove them
curl -X DELETE "https://ocidex.example.com/api/v1/namespaces/<namespace id>/members/<user id>" \
  -H "Authorization: Bearer $OCIDEX_API_KEY"
```
:::

## API keys

Scripts, CI, the CLI, the MCP server and the inventory agent all use API keys. A key acts for the
user who made it, limited to the capabilities you give it. It is shown **once**, when it's
created: copy it then.

- **In the UI:** **Admin → API Keys**. Name the key, and choose its capabilities and how long it
  lives (never, 30 or 90 days, or a year). The list shows each key's expiry and marks expired keys.
- **With the CLI:** `ocidex-cli key create --name ci --capability ingest`, plus `--expires-in 720h`
  for a key that expires. The key is printed on stdout and nowhere else.

Give each key only what its job needs:

| Job | Capabilities |
| --- | --- |
| CI pushing SBOMs | `ingest` |
| The inventory agent | `push_inventory` |
| Read-only scripts, dashboards, the MCP server | `read_private` |

A key can never do more than its owner's roles allow, so lowering someone's role narrows every key
they hold at once. Delete a key you no longer need from the same list, or with
`ocidex-cli key delete <id>`.

:::note
In this release the **API Keys** tab is shown only to installation admins. Other users create
their first key with the API (`POST /api/v1/auth/keys`) from a signed-in browser session, and can
use `ocidex-cli key create` from then on. An admin can't create a key for you: a key always acts
for the user who made it.
:::

## Your account

**Admin → Account** shows who you're signed in as, and lets you link a second sign-in provider to
your account, or unlink one.
