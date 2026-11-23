import { Show } from "solid-js";
import type { JSX } from "solid-js";
import type { VulnSummary } from "~/api/client";
import type { StatTile } from "./ui/StatBand";
import { SeverityPill } from "./VulnBadge";
import { StatusChip } from "~/components/ui/StatusChip";
import { VULN_DATA_STATUS } from "~/utils/status";
import { fixSplitLabel } from "~/utils/vuln";
import { formatDelta, type CriticalChange } from "~/utils/versionDelta";

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

/** breakdownTitle lists every non-zero severity, for the remainder's tooltip. */
function breakdownTitle(v: VulnSummary): string {
    return [
        { label: "critical", count: v.critical },
        { label: "high", count: v.high },
        { label: "medium", count: v.medium },
        { label: "low", count: v.low },
        { label: "unknown", count: v.unknown },
    ]
        .filter((r) => r.count > 0)
        .map((r) => `${r.count} ${r.label}`)
        .join(", ");
}

/**
 * The caption. "no known vulnerabilities" is a claim about what has been
 * scanned, so it is only made when a summary exists — something never scanned
 * says so instead of reading as clean. That is the same distinction ADR-044
 * insists on for unmatched cluster workloads: unknown must never read as clean.
 */
function VulnTileSub(props: { vulns: VulnSummary | undefined; matched?: boolean; change?: CriticalChange }) {
    return (
        <Show
            when={props.vulns !== undefined}
            fallback={
                // Matched with no findings is clean; otherwise it is unknown (ADR-044).
                <StatusChip status={props.matched === true ? VULN_DATA_STATUS.clean : VULN_DATA_STATUS.unscanned} />
            }
        >
            <Show when={worstSeverity(props.vulns)} fallback={<>no known vulnerabilities</>}>
                {(w) => (
                    <>
                        <SeverityPill severity={w().label}>
                            {w().count} {w().label}
                        </SeverityPill>
                        {/* The change since the version before it, beside the count
                            it changes. It is a critical delta, so it says so
                            unless the pill already does. */}
                        <Show when={props.change}>
                            {(c) => (
                                <span
                                    class="tile-delta"
                                    classList={{ "tile-delta-worse": c().delta > 0 }}
                                    title={`Critical findings compared with ${c().previous}`}
                                >
                                    {" "}
                                    {formatDelta(c().delta)}
                                    {w().label === "critical" ? "" : " critical"} vs {c().previous}
                                </span>
                            )}
                        </Show>
                        {/* The remainder, so the line adds up to the number above
                            it: the worst alone read as "1 medium" under a 3
                            (ocidex-nps9.10). The full breakdown is on hover. */}
                        <Show when={(props.vulns?.total ?? 0) - w().count > 0 ? props.vulns : undefined}>
                            {(v) => (
                                <span class="text-muted" title={breakdownTitle(v())}>
                                    {" "}+{v().total - w().count} other
                                </span>
                            )}
                        </Show>
                    </>
                )}
            </Show>
            <Show when={fixSplitLabel(props.vulns)}>{(l) => <span class="tile-fix">{l()}</span>}</Show>
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
 *
 * `scope` says what set of SBOMs the count was taken over (ocidex-7gf7.7). The
 * three bands that share this tile count over three different sets — one SBOM,
 * an artifact's latest version, the whole corpus — and rendered identically,
 * so the number read as the same kind of number in all three. It rides beside
 * the head rather than in the sub-line, which already carries worst severity.
 */
export function vulnTile<T extends string>(
    vulns: VulnSummary | undefined,
    id?: T,
    scope?: JSX.Element,
    /** The counted SBOM was matched, so an absent summary means zero, not unknown. */
    matched?: boolean,
    /** How the critical count changed from the version before, where one compares. */
    change?: CriticalChange,
): StatTile<T> {
    return {
        id,
        head: (
            <>
                Vulnerabilities
                <Show when={scope !== undefined}>
                    <span class="tile-scope">{scope}</span>
                </Show>
            </>
        ),
        value: vulns?.total ?? (matched === true ? 0 : "—"),
        // Severity rides in the sub-line as a SeverityPill rather than as a
        // colour on the number: the shared redscale (`sev-*`) is a set of badge
        // *backgrounds*, so applying it to `.tile-value` would paint a
        // full-bleed block behind the count instead of tinting it.
        sub: <VulnTileSub vulns={vulns} matched={matched} change={change} />,
    };
}
