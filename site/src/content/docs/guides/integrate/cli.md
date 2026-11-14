---
title: ocidex-cli
description: Install and configure ocidex-cli, and use it from scripts.
sidebar:
  order: 2
---

`ocidex-cli` is the command-line client for the OCIDex API. Commands are noun then verb:
`ocidex-cli sbom push`, `ocidex-cli registry list`. Every command and flag is in the
[CLI reference](/reference/cli/).

## Install

```sh
# With a Go toolchain
go install github.com/pfenerty/ocidex/cmd/ocidex-cli@latest

# Without one
docker run --rm ghcr.io/pfenerty/ocidex-cli:<version> --help
```

## Configure

```sh
ocidex-cli login --server-url https://ocidex.example.com
```

`login` prompts for an API key, checks it against the server, and only then writes
`~/.config/ocidex/config.yaml`, readable only by you. A key that doesn't work is refused there and
then, not at the next command.

Settings are resolved in this order, most specific first:

1. a command-line flag (`--server`, `--output`);
2. an environment variable (`OCIDEX_URL`, `OCIDEX_API_KEY`);
3. the config file;
4. the built-in default.

The API key is deliberately **not** a flag on everyday commands: a command-line argument shows up
in the process table and in most CI logs. In CI, set `OCIDEX_API_KEY` from a secret.

## Output

`--output table` (the default) is for people. `--output json` and `--output yaml` are for scripts:
a list prints as an array of the API's own objects, and a single item as one object.

```sh
ocidex-cli artifact list -o json | jq -r '.[].name'
```

## Exit codes

Scripts can branch on why a command failed:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Failure: the server or the network. |
| 2 | Usage: a bad flag or argument. Usage is printed with the message. |
| 3 | Not found. |
| 4 | Forbidden: the key isn't allowed to see or do it. |

## Common tasks

```sh
# Create a key for CI that can only upload SBOMs. It's printed once, on stdout.
ocidex-cli key create --name ci --capability ingest > ci-key.txt

# Create an upload source for it to push to
ocidex-cli source create --name ci --namespace acme

# Push an SBOM for a binary you built
ocidex-cli sbom push ./myapp.cdx.json --source acme/ci \
  --artifact-file ./bin/myapp --subject-type application --subject-name myapp \
  --version v1.4.2 --arch amd64

# What changed between the last two versions?
ocidex-cli artifact changelog <artifact id> --limit 1

# Re-scan a registry now
ocidex-cli registry scan <registry id>
```
