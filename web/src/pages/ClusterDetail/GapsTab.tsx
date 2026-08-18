import { Show } from "solid-js";
import { Card, CardHeader } from "~/components/ui";
import DataTable from "~/components/DataTable";
import { plural } from "~/utils/format";
import type { WorkloadCoverage } from "~/api/client";
import { useClusterWorkloads } from "~/api/queries";
import { workloadColumns } from "./WorkloadsTab";

/**
 * GapsTab is the actionable half of the coverage band: the containers OCIDex
 * cannot say anything about, split by *why*.
 *
 * The two sections are separate because the remedies are: an unknown digest is
 * an image nobody has ingested, which OCIDex can fix by scanning it; an
 * unresolvable one is a node runtime reporting a local image ID, which no
 * amount of scanning will help.
 */
export function GapsTab(props: { clusterId: string; coverage: WorkloadCoverage }) {
    const unknown = useClusterWorkloads(
        () => props.clusterId,
        () => ({ match_state: "unknown" as const, limit: 200 }),
    );
    const unresolvable = useClusterWorkloads(
        () => props.clusterId,
        () => ({ match_state: "unresolvable" as const, limit: 200 }),
    );

    return (
        <>
            <Card style={{ "margin-bottom": "1rem" }}>
                <CardHeader title="No SBOM ingested" count={props.coverage.unknown} />
                <p class="text-muted">
                    These containers report a registry-addressable digest that matches nothing in
                    the catalog. Ingesting the image is what closes this gap.
                </p>
                <DataTable
                    columns={workloadColumns}
                    rows={unknown.data?.data}
                    loading={unknown.isLoading}
                    isError={unknown.isError}
                    error={unknown.error}
                    emptyTitle="Every reported digest matched"
                    emptyMessage="No running container is missing an SBOM."
                />
            </Card>

            <Card>
                <CardHeader title="No digest readable" count={props.coverage.unresolvable} />
                <p class="text-muted">
                    The runtime reported a local image ID rather than a registry digest for these
                    containers, so they cannot be matched to any SBOM at all. This is a node
                    runtime problem, not a catalog one — scanning the image will not help.
                </p>
                <DataTable
                    columns={workloadColumns}
                    rows={unresolvable.data?.data}
                    loading={unresolvable.isLoading}
                    isError={unresolvable.isError}
                    error={unresolvable.error}
                    emptyTitle="Every container reported a digest"
                    emptyMessage="No running container is unmatchable."
                />
            </Card>

            <Show when={props.coverage.unknown + props.coverage.unresolvable === 0}>
                <p class="text-muted" style={{ "margin-top": "1rem" }}>
                    All {plural(props.coverage.total, "running container")} matched an ingested
                    SBOM.
                </p>
            </Show>
        </>
    );
}
