import { A } from "@solidjs/router";
import type { WorkloadCoverage } from "~/api/client";

/**
 * CoverageBand is the honest header for everything below it: how much of what
 * is running OCIDex can actually say something about.
 *
 * It comes before the vulnerability totals on purpose. A "0 known
 * vulnerabilities" figure computed over 3 of 40 running containers is not a
 * clean bill of health, and the only way a reader can tell is if the coverage
 * is stated first (ADR-044 K5).
 *
 * Every tile is a link into the tab that lists the rows behind it. Tiles used
 * to be tinted red whenever a gap existed, which on a real cluster is always —
 * a warning that is permanently on says nothing, and offered nothing to do
 * about it. The gap is now stated in the value's colour and its sub-label, and
 * the tint marks which tile you are looking at.
 */
export function CoverageBand(props: {
    coverage: WorkloadCoverage;
    clusterId: string;
    /** The tab currently shown, so the tile that produced it reads as selected. */
    active: string;
    activeMatchState?: string;
}) {
    const pct = () =>
        props.coverage.total === 0
            ? "—"
            : `${Math.round((props.coverage.matched / props.coverage.total) * 100).toString()}%`;

    const href = (query: string) => `/clusters/${props.clusterId}?${query}`;
    const cls = (selected: boolean, gap = false) =>
        ["coverage-tile", gap ? "gap" : "", selected ? "selected" : ""]
            .filter((c) => c !== "")
            .join(" ");
    const onWorkloads = (state?: string) =>
        props.active === "workloads" && props.activeMatchState === state;

    return (
        <div class="coverage-band">
            <A class={cls(onWorkloads(undefined))} href={href("tab=workloads")}>
                <span class="coverage-tile-head">Containers</span>
                <span class="coverage-tile-value">{props.coverage.total.toLocaleString()}</span>
                <span class="coverage-tile-sub">running, deduplicated per image</span>
            </A>
            <A class={cls(onWorkloads("exact"))} href={href("tab=workloads&match_state=exact")}>
                <span class="coverage-tile-head">Matched</span>
                <span class="coverage-tile-value">{props.coverage.matched.toLocaleString()}</span>
                <span class="coverage-tile-sub">{pct()} of what is running</span>
            </A>
            <A
                class={cls(props.active === "gaps", props.coverage.unknown > 0)}
                href={href("tab=gaps")}
            >
                <span class="coverage-tile-head">No SBOM</span>
                <span class="coverage-tile-value">{props.coverage.unknown.toLocaleString()}</span>
                <span class="coverage-tile-sub">not assessed — ingest to fix</span>
            </A>
            <A
                class={cls(props.active === "gaps", props.coverage.unresolvable > 0)}
                href={href("tab=gaps")}
            >
                <span class="coverage-tile-head">Unresolvable</span>
                <span class="coverage-tile-value">
                    {props.coverage.unresolvable.toLocaleString()}
                </span>
                <span class="coverage-tile-sub">no digest readable — runtime gap</span>
            </A>
        </div>
    );
}
