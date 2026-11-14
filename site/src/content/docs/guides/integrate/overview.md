---
title: Integrator guide
description: Drive OCIDex from the REST API, ocidex-cli, an MCP client and your CI.
sidebar:
  order: 0
---

Everything the UI does goes through a public REST API, and three clients are built on it.

| Use | When |
| --- | --- |
| [The REST API](/guides/integrate/api/) | Any language, any tool. Its full [reference](/reference/api/) is generated from the server. |
| [ocidex-cli](/guides/integrate/cli/) | Scripts and CI jobs: push SBOMs, query artifacts, manage registries and keys. |
| [The MCP server](/guides/integrate/mcp/) | Ask an AI agent about your SBOMs, diffs and vulnerabilities. |
| [The Go SDK](/guides/integrate/api/#go-sdk) | Go programs. `ocidex-cli` and the operator use it. |

To get SBOMs in from your build pipeline, start with [Push SBOMs from CI](/guides/integrate/ci/).

Every client authenticates with an **API key**. Create one under **Admin → API Keys**, or with
`ocidex-cli key create`. Give it only the capabilities it needs: a CI key that uploads SBOMs needs
`ingest` and nothing else. See [Namespaces and access](/concepts/namespaces-and-access/#api-keys).
