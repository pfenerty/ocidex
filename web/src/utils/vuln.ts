export function aliasUrl(id: string): string {
    if (id.startsWith("CVE-"))     return `https://nvd.nist.gov/vuln/detail/${id}`;
    if (id.startsWith("GHSA-"))    return `https://github.com/advisories/${id}`;
    if (id.startsWith("GO-"))      return `https://pkg.go.dev/vuln/${id}`;
    if (id.startsWith("PYSEC-"))   return `https://osv.dev/vulnerability/${id}`;
    if (id.startsWith("RUSTSEC-")) return `https://rustsec.org/advisories/${id}`;
    return `https://osv.dev/vulnerability/${id}`;
}

export interface CvssMetric {
    label: string;
    variant: string; // "danger" | "warning" | "" (muted)
}

// Metric decode tables for CVSS v3.x
// variant="" means show the chip but unstyled (muted); label="" means skip the chip.
const AV: Record<string, CvssMetric> = {
    N: { label: "Network",  variant: "danger" },
    A: { label: "Adjacent", variant: "warning" },
    L: { label: "Local",    variant: "" },
    P: { label: "Physical", variant: "" },
};
const AC: Record<string, CvssMetric> = {
    L: { label: "Low Complexity",  variant: "warning" },
    H: { label: "High Complexity", variant: "" },
};
const PR: Record<string, CvssMetric> = {
    N: { label: "No Privileges",   variant: "danger" },
    L: { label: "Low Privileges",  variant: "warning" },
    H: { label: "High Privileges", variant: "" },
};
const UI: Record<string, CvssMetric> = {
    N: { label: "No Interaction",       variant: "warning" },
    R: { label: "Requires Interaction", variant: "" },
};
const S: Record<string, CvssMetric> = {
    C: { label: "Scope Changed",    variant: "warning" },
    U: { label: "",                 variant: "" }, // Unchanged — omit
};
const IMPACT: Record<string, CvssMetric> = {
    H: { label: "High", variant: "danger" },
    L: { label: "Low",  variant: "warning" },
    N: { label: "",     variant: "" }, // None — omit
};

const V3_METRICS: Record<string, Record<string, CvssMetric>> = { AV, AC, PR, UI, S, C: IMPACT, I: IMPACT, A: IMPACT };
// Human-readable prefix for impact chips: "High C" not just "High"
const IMPACT_SUFFIX: Record<string, string> = { C: " C", I: " I", A: " A" };

// Metric decode tables for CVSS v4.0. AV/AC/PR share v3's semantics and tables;
// AT is new (no v3 equivalent), UI's values differ from v3, Scope (S) is gone,
// and C/I/A are split into Vulnerable-system (VC/VI/VA) and Subsequent-system (SC/SI/SA).
const AT: Record<string, CvssMetric> = {
    N: { label: "",                    variant: "" }, // None — omit
    P: { label: "Attack Requirements", variant: "warning" },
};
const UI_V4: Record<string, CvssMetric> = {
    N: { label: "No Interaction",      variant: "warning" },
    P: { label: "Passive Interaction", variant: "" },
    A: { label: "Active Interaction",  variant: "" },
};

const V4_METRICS: Record<string, Record<string, CvssMetric>> = {
    AV, AC, PR, AT, UI: UI_V4,
    VC: IMPACT, VI: IMPACT, VA: IMPACT,
    SC: IMPACT, SI: IMPACT, SA: IMPACT,
};
const V4_IMPACT_SUFFIX: Record<string, string> = {
    VC: " VC", VI: " VI", VA: " VA",
    SC: " SC", SI: " SI", SA: " SA",
};

export function parseCvssVector(vector: string): { version: string; metrics: CvssMetric[] } | null {
    if (!vector) return null;
    const parts = vector.split("/");
    if (parts.length < 2) return null;

    const prefix = parts[0]; // e.g. "CVSS:3.1" or "CVSS:4.0"
    const version = prefix.startsWith("CVSS:") ? `CVSSv${prefix.slice(5)}` : "CVSS";
    const isV4 = prefix.startsWith("CVSS:4");

    const metrics: CvssMetric[] = [];
    const lookup = (isV4 ? V4_METRICS : V3_METRICS) as Partial<Record<string, Partial<Record<string, CvssMetric>>>>;
    const suffixes = isV4 ? V4_IMPACT_SUFFIX : IMPACT_SUFFIX;
    for (const part of parts.slice(1)) {
        const colon = part.indexOf(":");
        if (colon < 0) continue;
        const key = part.slice(0, colon);
        const val = part.slice(colon + 1);
        const table = lookup[key];
        if (table === undefined) continue;
        const decoded = table[val];
        if (!decoded?.label) continue; // skip omitted metrics (empty label = hide chip)
        const suffix = suffixes[key] ?? "";
        metrics.push({ label: decoded.label + suffix, variant: decoded.variant });
    }

    return metrics.length > 0 ? { version, metrics } : null;
}

// cvssVersion extracts "CVSSv3.1" from a full vector string like "CVSS:3.1/AV:N/..."
export function cvssVersion(vector: string): string {
    const slash = vector.indexOf("/");
    const prefix = slash < 0 ? vector : vector.slice(0, slash);
    return prefix.startsWith("CVSS:") ? `CVSSv${prefix.slice(5)}` : "CVSS";
}
