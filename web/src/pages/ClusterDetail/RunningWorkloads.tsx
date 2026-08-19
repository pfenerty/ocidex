import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { useVulnWorkloads } from "~/api/queries";
import { imageRefName } from "~/utils/oci";
import "./RunningWorkloads.css";

/**
 * RunningWorkloadsList answers "where is this actually running" for one
 * advisory. Pass a clusterId to scope it to a cluster; omit it to span every
 * cluster the caller can see.
 *
 * Its query is gated by `when` because it is mounted once per row of a table:
 * fetching every advisory's workloads up front would be one request per row for
 * an answer nobody asked for yet.
 */
export function RunningWorkloadsList(props: {
    canonicalId: string;
    clusterId?: string;
    when: boolean;
    showCluster?: boolean;
    limit?: number;
}) {
    const query = useVulnWorkloads(
        () => props.canonicalId,
        () => props.clusterId,
        () => ({ enabled: props.when, ...(props.limit === undefined ? {} : { limit: props.limit }) }),
    );

    return (
        <Show when={props.when}>
            <Show
                when={!query.isLoading}
                fallback={<p class="text-muted text-sm">Loading workloads…</p>}
            >
                <Show
                    when={(query.data?.data.length ?? 0) > 0}
                    fallback={
                        <p class="text-muted text-sm">
                            No running workload matched. This advisory reaches you through images
                            OCIDex has, not images it has seen running.
                        </p>
                    }
                >
                    <ul class="running-workloads">
                        <For each={query.data?.data}>
                            {(w) => (
                                <li>
                                    <Show when={props.showCluster}>
                                        <A href={`/clusters/${w.cluster_id}`}>
                                            {w.cluster_name}
                                        </A>
                                        <span class="text-muted"> · </span>
                                    </Show>
                                    <span class="text-muted">{w.k8s_namespace}/</span>
                                    {w.workload_name}
                                    <span class="text-muted"> · {w.container_name}</span>
                                    <Show when={imageRefName(w.image_ref)}>
                                        {(name) => (
                                            <span class="text-muted font-mono text-sm"> {name()}</span>
                                        )}
                                    </Show>
                                    <span class="text-muted text-sm">
                                        {" "}
                                        ({w.pod_count.toLocaleString()}{" "}
                                        {w.pod_count === 1 ? "pod" : "pods"})
                                    </span>
                                </li>
                            )}
                        </For>
                    </ul>
                </Show>
            </Show>
        </Show>
    );
}
