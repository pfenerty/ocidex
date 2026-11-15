import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { Card } from "~/components/ui";
import type { WorkloadCoverage } from "~/api/client";
import { plural } from "~/utils/format";

/**
 * CoverageBand is the honest header for everything below it: how much of what
 * is running OCIDex can actually say something about (ADR-044 K5).
 *
 * One segmented bar rather than four tiles (ocidex-70eo.7, design Q4): the
 * tiles stated four numbers but not their proportion, and all four looked
 * selected at once. Each legend entry links to the rows behind it, and the
 * entry for the view on screen is marked, so selection stays visible without
 * outlining anything.
 */
export function CoverageBand(props: {
    coverage: WorkloadCoverage;
    clusterId: string;
    /** The tab currently shown, so the entry that produced it reads as selected. */
    active: string;
    activeMatchState?: string;
}) {
    const href = (query: string) => `/clusters/${props.clusterId}?${query}`;
    const pct = (n: number) =>
        props.coverage.total === 0 ? 0 : (n / props.coverage.total) * 100;

    const segments = () => [
        {
            key: "matched",
            n: props.coverage.matched,
            label: "matched to an SBOM",
            href: href("tab=workloads&matchState=exact"),
            selected: props.active === "workloads" && props.activeMatchState === "exact",
            gap: false,
        },
        {
            key: "unknown",
            n: props.coverage.unknown,
            label: "no SBOM · ingest to fix",
            href: href("tab=gaps"),
            selected: props.active === "gaps",
            gap: true,
        },
        {
            key: "unresolvable",
            n: props.coverage.unresolvable,
            label: "no digest readable · runtime gap",
            href: href("tab=gaps"),
            selected: false,
            gap: true,
        },
    ];

    return (
        <Card as="section" class="coverage-band" aria-label="Coverage">
            <div class="coverage-band-head">
                <A
                    href={href("tab=workloads")}
                    class={
                        props.active === "workloads" && props.activeMatchState === undefined
                            ? "coverage-total selected"
                            : "coverage-total"
                    }
                    activeClass="coverage-segment-route"
                >
                    {plural(props.coverage.total, "workload container")} · {plural(props.coverage.pods, "pod")}
                </A>
                <Show when={props.coverage.total > 0}>
                    <span class="text-muted text-sm">
                        every vulnerability figure on this page covers the matched{" "}
                        {props.coverage.matched.toLocaleString()}
                    </span>
                </Show>
            </div>
            <div class="coverage-bar" role="img" aria-label={`${Math.round(pct(props.coverage.matched))}% matched`}>
                <For each={segments()}>
                    {(s) => (
                        <Show when={s.n > 0}>
                            <i class={`coverage-bar-${s.key}`} style={{ width: `${pct(s.n)}%` }} />
                        </Show>
                    )}
                </For>
            </div>
            <div class="coverage-legend">
                <For each={segments()}>
                    {(s) => (
                        <A
                            href={s.href}
                            class={[
                                "coverage-segment",
                                `coverage-segment-${s.key}`,
                                s.gap && s.n > 0 ? "gap" : "",
                                s.selected ? "selected" : "",
                            ]
                                .filter((c) => c !== "")
                                .join(" ")}
                            // The router marks a link active on a path match, and every
                            // entry's path is this page; selection is ours to decide.
                            activeClass="coverage-segment-route"
                        >
                            <i aria-hidden="true" />
                            <strong>{s.n.toLocaleString()}</strong> {s.label}
                        </A>
                    )}
                </For>
            </div>
        </Card>
    );
}
