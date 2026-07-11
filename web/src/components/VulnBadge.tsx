import "./VulnBadge.css";
import { Show, For } from "solid-js";
import type { VulnSummary } from "~/api/client";
import { StatusPill } from "~/components/ui/Badge";
import type { BadgeVariant } from "~/components/ui/Badge";

export function severityVariant(severity: string | undefined): BadgeVariant {
    switch ((severity ?? "").toUpperCase()) {
        case "CRITICAL":
        case "HIGH":
            return "danger";
        case "MEDIUM":
            return "warning";
        default:
            return "default";
    }
}

// severityBadgeClass is kept for backward compatibility.
export function severityBadgeClass(severity: string | undefined): string {
    const v = severityVariant(severity);
    return v === "default" ? "badge" : `badge-${v}`;
}

// VulnBadge renders a per-component vulnerability indicator: the count coloured
// by the component's highest severity. Renders nothing when there are no vulns.
export function VulnBadge(props: { count: number | undefined; maxSeverity: string | undefined }) {
    return (
        <Show when={(props.count ?? 0) > 0} fallback={<span class="text-muted">—</span>}>
            <StatusPill
                variant={severityVariant(props.maxSeverity)}
                title={`${props.count} known ${props.count === 1 ? "vulnerability" : "vulnerabilities"} (max ${(props.maxSeverity ?? "unknown").toLowerCase()})`}
            >
                {props.count} {(props.maxSeverity ?? "").toLowerCase() || "vuln"}
            </StatusPill>
        </Show>
    );
}

// chipSeverityClass maps a severity to the VulnCountBadges chip's own color
// scale. Distinct from severityVariant/BadgeVariant: red and green read as
// the same hue under deuteranopia, so this scale never uses green — Critical
// and High stay in a redscale (distinguished by lightness, which survives
// deuteranopia, rather than hue), and Low gets blue instead of falling back
// to the gray shared with Unknown — matching the substitution already used
// for add/remove state in DiffEntry.tsx.
function chipSeverityClass(severity: string | undefined): string {
    switch ((severity ?? "").toUpperCase()) {
        case "CRITICAL":
            return "vuln-chip-critical";
        case "HIGH":
            return "vuln-chip-danger";
        case "MEDIUM":
            return "vuln-chip-warning";
        case "LOW":
            return "vuln-chip-low";
        default:
            return "vuln-chip-default";
    }
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
                    {(c) => <span class={`vuln-chip-n ${chipSeverityClass(c.severity)}`}>{c.count}</span>}
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
                        <StatusPill variant={severityVariant(c.severity)}>
                            {c.count} {c.label.toLowerCase()}
                        </StatusPill>
                    )}
                </For>
            </div>
        </Show>
    );
}
