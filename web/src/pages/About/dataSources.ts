/**
 * The vulnerability feeds OCIDex shows data from, and the terms each is
 * published under. docs/DATA_SOURCES.md is the source of truth; a test keeps
 * this list in step with its table (ocidex-7hhp).
 */
export interface DataSource {
    name: string;
    url?: string;
    usedFor: string;
    terms: string;
}

export const DATA_SOURCES: readonly DataSource[] = [
    {
        name: "GitHub Advisory Database",
        url: "https://github.com/github/advisory-database",
        usedFor: "Language ecosystems (Go, npm, PyPI, …)",
        terms: "CC-BY-4.0",
    },
    {
        name: "Go Vulnerability Database",
        url: "https://vuln.go.dev",
        usedFor: "Go modules and the standard library",
        terms: "CC-BY-4.0",
    },
    {
        name: "NVD",
        url: "https://nvd.nist.gov",
        usedFor: "CVE metadata, CVSS, CPE matching",
        terms: "US government work. This product uses data from the NVD API but is not endorsed or certified by the NVD.",
    },
    {
        name: "Ubuntu security data",
        url: "https://github.com/canonical/ubuntu-security-notices",
        usedFor: "Ubuntu packages",
        terms: "CC-BY-SA-4.0, © Canonical Ltd.",
    },
    {
        name: "Debian security tracker",
        url: "https://security-tracker.debian.org",
        usedFor: "Debian packages",
        terms: "Debian project, freely redistributable",
    },
    {
        name: "Red Hat security data",
        url: "https://access.redhat.com/security/data",
        usedFor: "RHEL packages",
        terms: "CC-BY-4.0",
    },
    {
        name: "Alpine, Wolfi, Chainguard, Amazon, Oracle, SUSE, Fedora, and other distro feeds",
        usedFor: "Their own packages",
        terms: "Per publisher",
    },
    {
        name: "FIRST EPSS",
        url: "https://www.first.org/epss",
        usedFor: "Exploit prediction scores",
        terms: "Free to use with attribution",
    },
    {
        name: "CISA KEV",
        url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        usedFor: "Known-exploited flag",
        terms: "US government work",
    },
];
