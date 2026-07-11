import "./VulnBadge.css";
import { Show, For } from "solid-js";
import type { JSX } from "solid-js";
import type { VulnSummary } from "~/api/client";

// severityColorClass maps a severity to a de-escalating redscale class,
// shared by every vulnerability display in the app — compact chips
// (VulnCountBadges) and full-size pills (SeverityPill) alike. Lightness,
// not hue, carries the distinction (red vs. green, or red vs. amber vs.
// blue, can collapse under deuteranopia; lightness contrast within one hue
// does not). Unknown is intentionally outside the scale — it isn't a
// severity — and stays neutral gray.
export function severityColorClass(severity: string | undefined): string {
    switch ((severity ?? "").toUpperCase()) {
        case "CRITICAL":
            return "sev-critical";
        case "HIGH":
            return "sev-high";
        case "MEDIUM":
            return "sev-medium";
        case "LOW":
            return "sev-low";
        default:
            return "sev-default";
    }
}

// SeverityPill renders a single full-size severity badge, colored via the
// shared redscale. Use where a labelled pill fits (detail pages, table
// cells); use VulnCountBadges for a compact multi-severity breakdown in
// tight spaces.
export function SeverityPill(props: { severity: string | undefined; title?: string; children: JSX.Element }) {
    return (
        <span class={`badge badge-sm ${severityColorClass(props.severity)}`} title={props.title}>
            {props.children}
        </span>
    );
}

// VulnBadge renders a per-component vulnerability indicator: the count coloured
// by the component's highest severity. Renders nothing when there are no vulns.
export function VulnBadge(props: { count: number | undefined; maxSeverity: string | undefined }) {
    return (
        <Show when={(props.count ?? 0) > 0} fallback={<span class="text-muted">—</span>}>
            <SeverityPill
                severity={props.maxSeverity}
                title={`${props.count} known ${props.count === 1 ? "vulnerability" : "vulnerabilities"} (max ${(props.maxSeverity ?? "unknown").toLowerCase()})`}
            >
                {props.count} {(props.maxSeverity ?? "").toLowerCase() || "vuln"}
            </SeverityPill>
        </Show>
    );
}

// VulnCountBadges renders a compact severity breakdown as a single seamless
// bar of solid-colored segments (e.g. "5 3 4 1 0" for
// critical|high|medium|low|unknown), each segment colored by its severity.
// Renders "—" when all counts are zero. Suitable for table cells and
// version summary rows across the app.
export function VulnCountBadges(props: {
    criticalCount?: number;
    highCount?: number;
    mediumCount?: number;
    lowCount?: number;
    unknownCount?: number;
}) {
    const counts = (): { label: string; severity: string; count: number }[] => [
        { label: "critical", severity: "CRITICAL", count: props.criticalCount ?? 0 },
        { label: "high", severity: "HIGH", count: props.highCount ?? 0 },
        { label: "medium", severity: "MEDIUM", count: props.mediumCount ?? 0 },
        { label: "low", severity: "LOW", count: props.lowCount ?? 0 },
        { label: "unknown", severity: "UNKNOWN", count: props.unknownCount ?? 0 },
    ];

    const total = () => counts().reduce((sum, c) => sum + c.count, 0);
    const title = () =>
        counts()
            .filter((c) => c.count > 0)
            .map((c) => `${c.count} ${c.label}`)
            .join(", ");

    return (
        <Show when={total() > 0} fallback={<span class="text-muted">—</span>}>
            <span class="vuln-chip" title={title()}>
                <For each={counts()}>
                    {(c) => <span class={`vuln-chip-n ${severityColorClass(c.severity)}`}>{c.count}</span>}
                </For>
            </span>
        </Show>
    );
}

// VulnSummaryBar renders the per-severity breakdown for an SBOM. Renders nothing
// when the SBOM has no known vulnerabilities.
export function VulnSummaryBar(props: { summary: VulnSummary | undefined }) {
    const cells = (): { label: string; severity: string; count: number }[] => {
        const s = props.summary;
        if (s === undefined) return [];
        return [
            { label: "Critical", severity: "CRITICAL", count: s.critical },
            { label: "High", severity: "HIGH", count: s.high },
            { label: "Medium", severity: "MEDIUM", count: s.medium },
            { label: "Low", severity: "LOW", count: s.low },
            { label: "Unknown", severity: "UNKNOWN", count: s.unknown },
        ].filter((c) => c.count > 0);
    };

    return (
        <Show when={(props.summary?.total ?? 0) > 0}>
            <div class="vuln-summary-bar">
                <span class="vuln-summary-total">
                    {props.summary?.total} known {props.summary?.total === 1 ? "vulnerability" : "vulnerabilities"}
                </span>
                <For each={cells()}>
                    {(c) => (
                        <SeverityPill severity={c.severity}>
                            {c.count} {c.label.toLowerCase()}
                        </SeverityPill>
                    )}
                </For>
            </div>
        </Show>
    );
}
