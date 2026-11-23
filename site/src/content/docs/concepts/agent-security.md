---
title: Agent security
description: How OCIDex limits what an AI agent can see and change, and what it treats as untrusted.
sidebar:
  order: 8
---

An agent acts for a person, but it is steered by text it reads, and some of that text was written by
strangers. OCIDex assumes an agent can be confused or manipulated, and bounds what a manipulated
agent can do on the server, where the agent cannot argue with it. How to set one up is in
[Agents](/guides/integrate/agents/). The decision record is ADR-0058.

## What a key may do

Every request is allowed only if all four of these allow it:

1. the owner's installation role;
2. the owner's role in the namespace, checked live, so removing them from a namespace removes
   their keys' access too;
3. the key's capabilities: the preset's for an agent key;
4. the key's namespaces: an agent key names them; a personal key may cover all of its owner's.

So a key is never stronger than its owner, and an administrator's agent key limited to one
namespace is refused everywhere else, exactly as a non-administrator's would be. The namespace limit
applies to reads as well as writes: private data from other namespaces does not appear in lists,
searches, counts or lookups, and asking for it by id answers "not found". Public data stays readable.

Some actions are never open to an agent key, whatever it carries: managing keys, approving or
denying requests, managing members, deleting a namespace, linking sign-in identities, and
installation administration.

Agent keys always expire, after at most 90 days.

## Approvals the agent cannot fake

A key can hold some of its capabilities for approval. A request that needs one is not run.
OCIDex stores the request as it arrived and describes its effect itself, from the request and the
current state. That description is what the approver reads. The agent's own explanation is shown
separately and marked as unverified, because an agent that has been manipulated would explain its
request persuasively.

On approval, the stored request runs exactly once. It is checked again at that moment: the key must
still be valid and its owner still allowed. The approver must be signed in to the web UI and able to
make the change themselves. No API key can approve, because the agent holds one. A denied or expired
request never runs.

MCP clients can also ask the user before a tool runs (elicitation). OCIDex uses that when the client
offers it, but does not rely on it: whether a client prompts is up to the client.

## Budgets

Agent keys have hourly budgets for changes and for scan requests. A runaway or manipulated agent
hits them whether or not anyone is watching. Held requests count when asked, so flooding a person
with approval requests is bounded too.

## Who did what

The audit log records an agent's action as its owner's, made through a named agent key and client,
by a named MCP tool, in the way RFC 8693 separates the subject from the actor. An approved request
records the approver and the requester separately. Each agent key's own activity, including
refusals and held requests, is listed on the Agents page.

## Untrusted data

Component names and descriptions, advisory text, image labels and registry tags come from third
parties. `ocidex-mcp` returns them as data: control characters and invisible formatting characters
are removed and long strings cut. The server's instructions tell the agent that tool results are
not instructions. That instruction is a mitigation, not a guarantee, which is why the limits above
are enforced by the server and not left to the agent.

## Limits

The smallest unit an agent key can be limited to is a namespace. "May scan only this registry"
cannot be expressed. Put things an agent should not touch in a namespace its key does not name.
