export function aliasUrl(id: string): string {
    if (id.startsWith("CVE-"))     return `https://nvd.nist.gov/vuln/detail/${id}`;
    if (id.startsWith("GHSA-"))    return `https://github.com/advisories/${id}`;
    if (id.startsWith("GO-"))      return `https://pkg.go.dev/vuln/${id}`;
    if (id.startsWith("PYSEC-"))   return `https://osv.dev/vulnerability/${id}`;
    if (id.startsWith("RUSTSEC-")) return `https://rustsec.org/advisories/${id}`;
    return `https://osv.dev/vulnerability/${id}`;
}
