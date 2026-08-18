import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { Card, CardHeader } from "~/components/ui";
import { SeverityPill } from "~/components/VulnBadge";
import { VulnId } from "~/components/cells";
import { plural } from "~/utils/format";
import type { WorkloadCoverage } from "~/api/client";
import { useClusterVulns } from "~/api/queries";

/**
 * OverviewTab answers "should I be looking at this cluster today?" and then
 * hands off: the running vulnerabilities that matter most, and the size of the
 * gap that qualifies them.
 *
 * The vulnerability list is deliberately short. It is a pointer into the
 * Vulnerabilities tab, not a second copy of it.
 */
export function OverviewTab(props: { clusterId: string; coverage: WorkloadCoverage }) {
    const topVulns = useClusterVulns(() => props.clusterId, () => ({ limit: 5 }));
    const notAssessed = () => props.coverage.unknown + props.coverage.unresolvable;
    const tabHref = (tab: string) => `/clusters/${props.clusterId}?tab=${tab}`;

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
        </>
    );
}
