---
title: Vulnerability matching
description: How OCIDex finds vulnerabilities in your SBOMs, and keeps them current.
sidebar:
  order: 4
---

OCIDex matches the packages in every SBOM against the [grype](https://github.com/anchore/grype)
vulnerability database. The vuln-worker downloads that database, matches each new SBOM within
about a minute of ingest, and matches everything again whenever a new database is published,
which is daily.

That last part is the point. **A new advisory reaches every affected SBOM without rescanning an
image.** The image you scanned six months ago shows the CVE published this morning.

## What a match carries

Each finding links a package version to an advisory, with:

- the **severity** and CVSS score;
- the **fixed version**, when one exists;
- a summary and links to the advisory.

A finding with a fixed version is one you can act on now: rebuild with the fixed package.

## Data sources

The grype database is built from public feeds: the GitHub Advisory Database, the Go vulnerability
database, NVD, the Ubuntu, Debian, Red Hat, Alpine, Wolfi and other distribution security
trackers, FIRST EPSS and CISA KEV. Each keeps its own license, and OCIDex shows advisory text as
published.

## Limits

A match is only as good as the SBOM. A package the SBOM doesn't list can't be matched, and a
package without a purl is matched less precisely. Distribution packages are matched against their
distribution's own tracker, which knows about backported fixes that a version comparison would
miss.
