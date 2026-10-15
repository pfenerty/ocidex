# Security Policy

## Supported versions

OCIDex is pre-1.0. Security fixes land on `main` and ship in the next release of the
**latest minor version** only; older minors are not patched. This table will be aligned
with the 1.0 support scope when it is decided.

| Version | Supported |
|---|---|
| Latest minor (currently `0.0.x`) | Yes |
| Anything older | No — upgrade |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/pfenerty/ocidex/security/advisories/new)**
(the *Security* tab of the repository → *Report a vulnerability*).

Please include:

- the affected component (API, a worker, the operator, the web UI, the Helm chart, a
  published image) and version or image digest;
- the steps or a minimal proof of concept that reproduces it;
- the impact as you understand it, and any configuration it depends on.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Initial assessment (confirmed or not, and severity) | within 10 business days |
| Fix or mitigation for a confirmed high or critical issue | within 30 days of confirmation |

This is a small project maintained on a best-effort basis; these are targets, not
contractual guarantees. You will be kept informed through the advisory thread.

## Disclosure

We follow coordinated disclosure. Once a fix is released, a GitHub Security Advisory is
published (with a CVE requested where appropriate) and the fix is called out in
[CHANGELOG.md](CHANGELOG.md). We ask that you hold details until then, or for 90 days
from your report, whichever comes first; if we need longer we will say why. Reporters
are credited in the advisory unless they ask not to be.

## Verifying releases

Every published image (`ghcr.io/pfenerty/ocidex-*`) is signed and carries build
provenance and an SBOM. See [docs/verifying-artifacts.md](docs/verifying-artifacts.md) for
how to verify them, and [`cosign.pub`](cosign.pub) for the signing key.
