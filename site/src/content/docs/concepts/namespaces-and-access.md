---
title: Namespaces and access
description: Who can see and change what in OCIDex.
sidebar:
  order: 6
---

A **namespace** owns things: sources, clusters, and every artifact and SBOM that came in through
them. It is the unit of access. A team, a product or a tenant usually gets one.

## Visibility

A namespace is **public** or **private**.

- Everything in a **public** namespace is visible to everyone who can reach OCIDex, signed in or
  not.
- Everything in a **private** namespace is visible only to its members and to installation admins.

## Members and roles

Each member of a namespace has one role. Roles grant capabilities, and every action needs one.

| Capability | owner | maintainer | security | developer | viewer |
| --- | :-: | :-: | :-: | :-: | :-: |
| Read private content | ✓ | ✓ | ✓ | ✓ | ✓ |
| Ingest SBOMs | ✓ | ✓ | | ✓ | |
| Trigger a scan | ✓ | ✓ | ✓ | ✓ | |
| Push cluster inventory | ✓ | ✓ | | ✓ | |
| Delete artifacts | ✓ | ✓ | | | |
| Manage sources and clusters | ✓ | ✓ | | | |
| Read registry credentials | ✓ | ✓ | | | |
| Manage members | ✓ | | | | |
| Delete the namespace | ✓ | | | | |

Two of these are deliberate:

- **security** can re-scan but not ingest. Confirming a fix landed shouldn't need the right to
  publish.
- **developer** is shaped for CI: read, ingest, push inventory and re-scan, and change nothing else.

Each namespace has exactly one owner. An **installation admin** can do anything in any namespace.

## API keys

An API key acts for the user who made it. It can also carry a list of capabilities, which is a
ceiling: the key can do what is on the list **and** what its owner's roles allow, checked on every
request. So a key is never stronger than its owner, and narrowing someone's role narrows all their
keys at once.

Give a CI key only the capabilities its job needs. A pipeline that uploads SBOMs needs `ingest`,
and without `push_inventory` it can't overwrite a cluster's inventory by mistake.

## Signing in

OCIDex signs users in with GitHub, or with any OpenID Connect provider, or both. An account can
link more than one identity.
