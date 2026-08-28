import { Show } from "solid-js";
import type { VulnSummary } from "~/api/client";
import type { StatTile } from "./ui/StatBand";
import { SeverityPill } from "./VulnBadge";

/**
 * The worst severity actually present, which is the figure that decides whether
 * something needs attention. A bare total flattens "1 critical" into the same
 * shape as "40 low".
 */
export function worstSeverity(
    v: VulnSummary | undefined,
): { label: string; count: number } | undefined {
    if (v === undefined) return undefined;
    return [
        { label: "critical", count: v.critical },
        { label: "high", count: v.high },
        { label: "medium", count: v.medium },
        { label: "low", count: v.low },
        { label: "unknown", count: v.unknown },
    ].find((r) => r.count > 0);
}

/**
 * The caption. "no known vulnerabilities" is a claim about what has been
 * scanned, so it is only made when a summary exists — something never scanned
 * says so instead of reading as clean. That is the same distinction ADR-044
 * insists on for unmatched cluster workloads: unknown must never read as clean.
 */
function VulnTileSub(props: { vulns: VulnSummary | undefined }) {
    return (
        <Show when={props.vulns !== undefined} fallback={<>not scanned</>}>
            <Show when={worstSeverity(props.vulns)} fallback={<>no known vulnerabilities</>}>
                {(w) => (
                    <SeverityPill severity={w().label}>
                        {w().count} {w().label}
                    </SeverityPill>
                )}
            </Show>
        </Show>
    );
}

/**
 * The vulnerability tile, shared so the SBOM band and the artifact band cannot
 * disagree about what "no vulnerabilities" means.
 *
 * Selectability is the caller's to grant: pass `id` on a page that has a
 * vulnerabilities tab to send the reader to, and omit it on one that does not.
 * StatBand renders an id-less tile as a plain <div> rather than a <button>,
 * which is the point — a tile that looks like a control and does nothing is
 * worse than a plain stat. The SBOM band passes "vulns" (ocidex-unn8.5).
 */
export function vulnTile<T extends string>(
    vulns: VulnSummary | undefined,
    id?: T,
): StatTile<T> {
    return {
        id,
        head: "Vulnerabilities",
        value: vulns?.total ?? "—",
        // Severity rides in the sub-line as a SeverityPill rather than as a
        // colour on the number: the shared redscale (`sev-*`) is a set of badge
        // *backgrounds*, so applying it to `.tile-value` would paint a
        // full-bleed block behind the count instead of tinting it.
        sub: <VulnTileSub vulns={vulns} />,
    };
}
