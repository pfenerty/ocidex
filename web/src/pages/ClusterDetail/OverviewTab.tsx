import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { Card, CardHeader } from "~/components/ui";
import { SeverityPill } from "~/components/VulnBadge";
import { VulnId } from "~/components/cells";
import { plural } from "~/utils/format";
import type { WorkloadCoverage } from "~/api/client";
import { useClusterVulns, useClusterUnknownImages } from "~/api/queries";

/**
 * OverviewTab answers "should I be looking at this cluster today?" and then
 * hands off: the running vulnerabilities that matter most, and the size of the
 * gap that qualifies them.
 *
 * The vulnerability list is deliberately short. It is a pointer into the
 * Vulnerabilities tab, not a second copy of it.
 */
export function OverviewTab(props: {
    clusterId: string;
    coverage: WorkloadCoverage;
    autoIngest: boolean;
}) {
    const topVulns = useClusterVulns(() => props.clusterId, () => ({ limit: 5 }));
    const notAssessed = () => props.coverage.unknown + props.coverage.unresolvable;
    const tabHref = (tab: string) => `/clusters/${props.clusterId}?tab=${tab}`;

    // Same limit as the Gaps tab so the two share one cached response rather
    // than fetching the gap list twice.
    const images = useClusterUnknownImages(
        () => props.clusterId,
        () => ({ enabled: props.coverage.unknown > 0, limit: 200 }),
    );
    const ready = () => (images.data?.data ?? []).filter((i) => i.reason === "ready").length;
    const blocked = () => (images.data?.data.length ?? 0) - ready();

    return (
        <>
            <Card style={{ "margin-bottom": "1rem" }}>
                <CardHeader
                    title="Most severe running vulnerabilities"
                    count={topVulns.data?.pagination.total}
                    actions={
                        <A href={tabHref("vulnerabilities")} class="dash-link">
                            See all
                        </A>
                    }
                />
                <Show
                    when={!topVulns.isLoading}
                    fallback={<p class="text-muted">Loading vulnerability counts…</p>}
                >
                    <Show
                        when={!topVulns.isError}
                        fallback={
                            <p class="text-muted">
                                Vulnerability counts could not be loaded for this cluster.
                            </p>
                        }
                    >
                        <Show
                            when={(topVulns.data?.data.length ?? 0) > 0}
                            fallback={
                                <p>
                                    No known vulnerability affects the{" "}
                                    {plural(props.coverage.matched, "matched container")} running
                                    here.
                                </p>
                            }
                        >
                            <ul class="overview-vuln-list">
                                <For each={topVulns.data?.data}>
                                    {(v) => (
                                        <li>
                                            <SeverityPill severity={v.severity}>
                                                {v.severity ?? "unknown"}
                                            </SeverityPill>
                                            <VulnId canonicalId={v.canonical_id} nativeId={v.id} />
                                            <span class="text-muted">
                                                {plural(v.workload_count, "workload")}
                                            </span>
                                        </li>
                                    )}
                                </For>
                            </ul>
                        </Show>
                    </Show>
                </Show>
                <Show when={notAssessed() > 0}>
                    <span class="coverage-caveat">
                        {plural(notAssessed(), "running container")} are excluded from these counts:{" "}
                        {props.coverage.unknown.toLocaleString()} have no ingested SBOM and{" "}
                        {props.coverage.unresolvable.toLocaleString()} have no readable digest.
                        Their exposure is unknown, not zero.{" "}
                        <A href={tabHref("gaps")} class="dash-link">
                            Close the gap
                        </A>
                    </span>
                </Show>
            </Card>

            {/*
              * Ingest status describes the gap as it stands right now, not a
              * history: nothing persists a last-attempt timestamp, and a line
              * claiming "last run 10:04" from memory the server does not hold
              * would be the kind of reassurance ADR-044 K5 exists to prevent.
              */}
            <Card>
                <CardHeader title="Ingest" />
                <Show
                    when={props.coverage.unknown > 0}
                    fallback={
                        <p class="text-muted">
                            Every running container with a readable digest matched an ingested
                            SBOM. There is nothing to ingest.
                        </p>
                    }
                >
                    <p class="text-muted">
                        <Show
                            when={props.autoIngest}
                            fallback={
                                <>
                                    Auto-ingest is <strong>off</strong> for this cluster, so an
                                    unscanned image stays unscanned until someone ingests it. Turn
                                    it on from the cluster list, or ingest the gap by hand.
                                </>
                            }
                        >
                            <>
                                Auto-ingest is <strong>on</strong>: each inventory push queues a
                                scan for every unscanned image whose registry this namespace
                                already has.
                            </>
                        </Show>{" "}
                        <Show when={!images.isLoading && !images.isError}>
                            {plural(ready(), "image")} can be ingested now
                            <Show when={blocked() > 0}>
                                {" "}
                                and {blocked().toLocaleString()} cannot — each for its own reason
                            </Show>
                            .{" "}
                        </Show>
                        <A href={tabHref("gaps")} class="dash-link">
                            Review the gap
                        </A>
                    </p>
                </Show>
            </Card>
        </>
    );
}
