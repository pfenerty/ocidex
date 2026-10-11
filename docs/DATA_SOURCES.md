# Vulnerability data sources and attribution

OCIDex matches components against the [grype](https://github.com/anchore/grype) vulnerability
database (ADR-049). Anchore builds it daily from the public feeds below, each under its own
terms. OCIDex stores and displays advisory text as published, without modification.

| Source | Used for | Terms |
|---|---|---|
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Language ecosystems (Go, npm, PyPI, …) | CC-BY-4.0 |
| [Go Vulnerability Database](https://vuln.go.dev) | Go modules and the standard library | CC-BY-4.0 |
| [NVD](https://nvd.nist.gov) | CVE metadata, CVSS, CPE matching | US government work. This product uses data from the NVD API but is not endorsed or certified by the NVD. |
| [Ubuntu security data](https://github.com/canonical/ubuntu-security-notices) | Ubuntu packages | CC-BY-SA-4.0, © Canonical Ltd. |
| [Debian security tracker](https://security-tracker.debian.org) | Debian packages | Debian project, freely redistributable |
| [Red Hat security data](https://access.redhat.com/security/data) | RHEL packages | CC-BY-4.0 |
| Alpine, Wolfi, Chainguard, Amazon, Oracle, SUSE, Fedora, and other distro feeds | Their own packages | Per publisher |
| [FIRST EPSS](https://www.first.org/epss) | Exploit prediction scores | Free to use with attribution |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited flag | US government work |

Advisory text from a share-alike source (Ubuntu) stays under that source's license. OCIDex
must not redistribute modified versions of it under other terms.
