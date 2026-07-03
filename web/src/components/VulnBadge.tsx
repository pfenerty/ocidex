import "./VulnBadge.css";
import { Show, For } from "solid-js";
import type { VulnSummary } from "~/api/client";

// severityBadgeClass maps a severity label to a badge variant from the design
// system. CRITICAL/HIGH read as danger, MEDIUM as warning, everything else muted.
export function severityBadgeClass(severity: string | undefined): string {
    switch ((severity ?? "").toUpperCase()) {
        case "CRITICAL":
        case "HIGH":
            return "badge-danger";
        case "MEDIUM":
            return "badge-warning";
        default:
            return "badge";
    }
}

// VulnBadge renders a per-component vulnerability indicator: the count coloured
// by the component's highest severity. Renders nothing when there are no vulns.
export function VulnBadge(props: { count: number | undefined; maxSeverity: string | undefined }) {
    return (
        <Show when={(props.count ?? 0) > 0} fallback={<span class="text-muted">—</span>}>
            <span
                class={`badge badge-sm ${severityBadgeClass(props.maxSeverity)}`}
                title={`${props.count} known ${props.count === 1 ? "vulnerability" : "vulnerabilities"} (max ${(props.maxSeverity ?? "unknown").toLowerCase()})`}
            >
                {props.count} {(props.maxSeverity ?? "").toLowerCase() || "vuln"}
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
                        <span class={`badge badge-sm ${severityBadgeClass(c.severity)}`}>
                            {c.count} {c.label.toLowerCase()}
                        </span>
                    )}
                </For>
            </div>
        </Show>
    );
}
