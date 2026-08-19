import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { Card, CardHeader, StatusPill } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { plural, shortDigest } from "~/utils/format";
import type { IngestReason, UnknownImage, WorkloadCoverage } from "~/api/client";
import { useClusterWorkloads, useClusterUnknownImages } from "~/api/queries";
import { workloadColumns } from "./WorkloadsTab";

/**
 * How each ingest reason is presented. Every one of them is a different thing
 * to do — add a registry, switch one on, widen its patterns, fix the node —
 * so a single "cannot ingest" would send everyone to the wrong remedy.
 */
const REASON_PRESENTATION: Record<
    IngestReason,
    { label: string; variant: "success" | "warning" | "danger" }
> = {
    ready: { label: "ready to ingest", variant: "success" },
    no_registry: { label: "no registry", variant: "danger" },
    registry_disabled: { label: "registry disabled", variant: "warning" },
    pattern_excluded: { label: "excluded by patterns", variant: "warning" },
    unparseable_ref: { label: "no host in reference", variant: "warning" },
};

/**
 * IngestTargetCell says what stands between this image and an SBOM.
 *
 * The registry is named whenever one was matched at all, including when it is
 * switched off or excludes the repository: "ghcr is disabled" is only
 * actionable if you know it is ghcr.
 */
function IngestTargetCell(props: { image: UnknownImage }) {
    const reason = () => REASON_PRESENTATION[props.image.reason];
    return (
        <div class="ingest-target">
            <StatusPill variant={reason().variant}>{reason().label}</StatusPill>
            <Show when={props.image.registry_id}>
                {(id) => (
                    <A href={`/registries/${id()}`} class="text-sm">
                        {props.image.registry_name ?? "registry"}
                    </A>
                )}
            </Show>
            <Show when={props.image.reason === "no_registry"}>
                <span class="text-muted text-sm">
                    nothing configured for{" "}
                    <span class="font-mono">{props.image.registry_host}</span> —{" "}
                    <A href="/registries">add a registry</A>
                </span>
            </Show>
            <Show when={props.image.reason === "unparseable_ref"}>
                <span class="text-muted text-sm">
                    the reported reference names no registry, so there is nothing to resolve
                </span>
            </Show>
        </div>
    );
}

const unknownImageColumns: Column<UnknownImage>[] = [
    {
        header: "Image",
        sortValue: (i) => i.image_ref,
        render: (i) => (
            <>
                <span class="font-mono text-sm">{i.image_ref}</span>
                <div class="text-muted text-sm font-mono">{shortDigest(i.image_digest)}</div>
            </>
        ),
    },
    {
        header: "Running as",
        render: (i) => (
            <>
                <span class="text-muted">{i.sample_k8s_namespace}/</span>
                {i.sample_workload_name}
                <Show when={i.workload_count > 1}>
                    <span class="text-muted text-sm">
                        {" "}
                        and {plural(i.workload_count - 1, "other container")}
                    </span>
                </Show>
            </>
        ),
    },
    {
        header: "Pods",
        align: "right",
        sortValue: (i) => i.pod_count,
        render: (i) => i.pod_count.toLocaleString(),
    },
    {
        header: "Ingest",
        sortValue: (i) => i.reason,
        render: (i) => <IngestTargetCell image={i} />,
    },
];

/**
 * GapsTab is the actionable half of the coverage band: the containers OCIDex
 * cannot say anything about, split by *why*.
 *
 * The two sections are separate because the remedies are: an unknown digest is
 * an image nobody has ingested, which OCIDex can fix by scanning it; an
 * unresolvable one is a node runtime reporting a local image ID, which no
 * amount of scanning will help.
 *
 * The No-SBOM section lists images rather than containers, because that is the
 * unit of the remedy — twelve replicas of one unscanned image are one thing to
 * ingest.
 */
export function GapsTab(props: { clusterId: string; coverage: WorkloadCoverage }) {
    const images = useClusterUnknownImages(
        () => props.clusterId,
        () => ({ limit: 200 }),
    );
    const unresolvable = useClusterWorkloads(
        () => props.clusterId,
        () => ({ match_state: "unresolvable" as const, limit: 200 }),
    );

    const ingestable = () =>
        (images.data?.data ?? []).filter((i) => i.reason === "ready").length;

    return (
        <>
            <Card style={{ "margin-bottom": "1rem" }}>
                <CardHeader title="No SBOM ingested" count={props.coverage.unknown} />
                <p class="text-muted">
                    These images report a registry-addressable digest that matches nothing in the
                    catalog. Ingesting the image is what closes this gap.
                    <Show when={(images.data?.data.length ?? 0) > 0}>
                        {" "}
                        {ingestable().toLocaleString()} of{" "}
                        {plural(images.data?.data.length ?? 0, "image")} can be ingested with the
                        registries this namespace already has.
                    </Show>
                </p>
                <DataTable
                    columns={unknownImageColumns}
                    rows={images.data?.data}
                    loading={images.isLoading}
                    isError={images.isError}
                    error={images.error}
                    emptyTitle="Every reported digest matched"
                    emptyMessage="No running container is missing an SBOM."
                />
            </Card>

            <Card>
                <CardHeader title="No digest readable" count={props.coverage.unresolvable} />
                <p class="text-muted">
                    The runtime reported a local image ID rather than a registry digest for these
                    containers, so they cannot be matched to any SBOM at all. This is a node
                    runtime problem, not a catalog one — scanning the image will not help. The
                    agent normalizes every <span class="font-mono">imageID</span> form it
                    recognises; what reaches here reported an image ID with no repository digest
                    in it, which the dockershim-era runtimes do. Upgrading the node runtime is
                    the remedy.
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
