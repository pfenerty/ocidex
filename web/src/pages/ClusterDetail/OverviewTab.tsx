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
    clusterName: string;
    coverage: WorkloadCoverage;
    autoIngest: boolean;
    lastSeenAt: string | undefined;
}) {
    const topVulns = useClusterVulns(() => props.clusterId, () => ({ limit: 5 }));
    const notAssessed = () => props.coverage.unknown + props.coverage.unresolvable;
    const tabHref = (tab: string) => `/clusters/${props.clusterId}?tab=${tab}`;

    // One row is enough: this line reports the shape of the whole gap, and the
    // server sends the reason tally and the total for the gap rather than for
    // the page. Counting a page here would have quietly capped both figures at
    // whatever the list happened to hold.
    const images = useClusterUnknownImages(
        () => props.clusterId,
        () => ({ enabled: props.coverage.unknown > 0, limit: 1 }),
    );
    const shown = () => topVulns.data?.data.length ?? 0;
    const ready = () => images.data?.reasons.ready ?? 0;
    const blocked = () => (images.data?.pagination.total ?? 0) - ready();

    const reported = () => (props.lastSeenAt ?? "") !== "";

    return (
        // A cluster nothing has ever reported has no inventory to summarise,
        // and cards reading "no known vulnerability affects 0 matched
        // containers" would be four ways of saying "clean" about a cluster
        // nobody has looked at (ADR-044 K5). Lead with what is missing.
        <Show
            when={reported()}
            fallback={<AgentSetup clusterId={props.clusterId} clusterName={props.clusterName} />}
        >
            <Card style={{ "margin-bottom": "1rem" }}>
                <CardHeader
                    // "Top 5 of 487", not a 487 badge beside five rows: the
                    // badge read as the length of the list under it.
                    title={
                        <>
                            Most severe running vulnerabilities
                            <Show when={shown() > 0}>
                                <span class="text-muted text-sm">
                                    {" "}
                                    top {shown().toLocaleString()} of{" "}
                                    {(topVulns.data?.pagination.total ?? shown()).toLocaleString()}
                                </span>
                            </Show>
                        </>
                    }
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
                            {/*
                              * One grid rather than five independent flex rows.
                              * Severity pills are different widths, so the old
                              * layout put every id at a different indent and
                              * nothing lined up to be compared down the column.
                              */}
                            <ul class="overview-vuln-list">
                                <For each={topVulns.data?.data}>
                                    {(v) => (
                                        <li>
                                            <SeverityPill severity={v.severity}>
                                                {v.severity ?? "unknown"}
                                            </SeverityPill>
                                            <VulnId canonicalId={v.canonical_id} nativeId={v.id} />
                                            <span class="overview-vuln-cvss text-muted">
                                                <Show when={v.cvss_score} fallback="—">
                                                    {(score) => <>{score().toFixed(1)}</>}
                                                </Show>
                                            </span>
                                            <span
                                                class="overview-vuln-summary"
                                                title={v.summary}
                                            >
                                                {v.summary}
                                            </span>
                                            <span class="text-muted text-sm">
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
        </Show>
    );
}

/**
 * AgentSetup is the Overview a cluster gets before its first snapshot.
 *
 * The registration and the reporting are two separate steps — ADR-044 puts the
 * agent in the target cluster, which may be nowhere near this one — so a
 * registered cluster with nothing in it is the expected first state, not a
 * fault. The commands carry the cluster's own id so there is nothing to
 * transcribe.
 */
function AgentSetup(props: { clusterId: string; clusterName: string }) {
    const install = () =>
        [
            "kubectl create namespace ocidex-agent",
            "kubectl -n ocidex-agent create secret generic ocidex-k8s-agent-secrets \\",
            '  --from-literal=OCIDEX_API_KEY="$OCIDEX_API_KEY"',
            "",
            "helm install ocidex-k8s-agent oci://ghcr.io/pfenerty/charts/ocidex-k8s-agent \\",
            "  -n ocidex-agent \\",
            `  --set server.url=${window.location.origin} \\`,
            `  --set cluster.id=${props.clusterId}`,
        ].join("\n");

    return (
        <Card>
            <CardHeader title="No agent has reported yet" />
            <p>
                <strong>{props.clusterName}</strong> is registered, but nothing has pushed an
                inventory to it. That is not the same as a cluster running nothing — until an
                agent reports, OCIDex knows nothing about what is running here.
            </p>
            <p class="text-muted">
                Run these against the target cluster&apos;s kubeconfig context, with an API key
                that has <code>read-write</code> scope and belongs to someone who owns this
                cluster&apos;s namespace.
            </p>
            <pre class="agent-setup-commands">{install()}</pre>
            <p class="text-muted">
                The agent reaches OCIDex from inside the target cluster, so{" "}
                <code>server.url</code> has to be routable and TLS-valid there. Verify with{" "}
                <code>kubectl -n ocidex-agent logs deploy/ocidex-k8s-agent</code>: an{" "}
                <code>inventory reported</code> line means the snapshot landed, and this page
                will fill in on the next refresh.
            </p>
        </Card>
    );
}
