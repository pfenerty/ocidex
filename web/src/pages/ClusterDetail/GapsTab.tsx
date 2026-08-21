import { Show, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import { Card, CardHeader, StatusPill } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { plural, shortDigest } from "~/utils/format";
import type { IngestReason, IngestResult, UnknownImage, WorkloadCoverage } from "~/api/client";
import { useClusterWorkloads, useClusterUnknownImages, useIngestUnknown } from "~/api/queries";
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
function IngestTargetCell(props: {
    image: UnknownImage;
    onIngest: (digest: string) => void;
    pending: boolean;
}) {
    const reason = () => REASON_PRESENTATION[props.image.reason];
    return (
        <div class="ingest-target">
            <StatusPill variant={reason().variant}>{reason().label}</StatusPill>
            <Show when={props.image.reason === "ready"}>
                <button
                    class="btn btn-sm"
                    disabled={props.pending}
                    onClick={() => props.onIngest(props.image.image_digest)}
                >
                    {props.pending ? "Queueing…" : "Ingest"}
                </button>
            </Show>
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

/**
 * unknownImageColumns is a factory rather than a constant because the last
 * column carries an action. Passing the handler in keeps the mutation owned by
 * the tab, so the bulk button and the row buttons share one pending state and
 * one result.
 */
function unknownImageColumns(
    onIngest: (digest: string) => void,
    pendingDigest: () => string | null,
): Column<UnknownImage>[] {
    return [
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
        render: (i) => (
            <IngestTargetCell
                image={i}
                onIngest={onIngest}
                pending={pendingDigest() === i.image_digest}
            />
        ),
    },
    ];
}

/**
 * ingestSummary reports what a run did, per reason.
 *
 * Every skip is named rather than folded into one number: "queued 3 of 9" with
 * no explanation of the other six is the shape of message that gets read as a
 * failure. Each reason here is a different job for the reader.
 */
function ingestSummary(res: IngestResult): string {
    const parts: string[] = [`Queued ${plural(res.queued, "scan job")}`];
    const skips: [number, string][] = [
        [res.skipped_no_registry, "no registry configured"],
        [res.skipped_registry_disabled, "registry disabled"],
        [res.skipped_pattern_excluded, "excluded by registry patterns"],
        [res.skipped_unparseable_ref, "no host in the reference"],
        [res.failed, "registry unreachable"],
    ];
    for (const [n, label] of skips) {
        if (n > 0) parts.push(`${n.toLocaleString()} skipped: ${label}`);
    }
    return `${parts.join(" · ")}. Scanning happens in the background — this list updates as workers finish.`;
}

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

    const ingestable = () => (images.data?.data ?? []).filter((i) => i.reason === "ready");

    const ingest = useIngestUnknown();
    // Which row is mid-flight, so only that row's button shows its own pending
    // label. A bulk run is not a row, hence null.
    const [pendingDigest, setPendingDigest] = createSignal<string | null>(null);

    const runIngest = (digests?: string[]) => {
        setPendingDigest(digests?.length === 1 ? digests[0] : null);
        ingest.mutate(
            { id: props.clusterId, imageDigests: digests },
            { onSettled: () => setPendingDigest(null) },
        );
    };

    return (
        <>
            <Card style={{ "margin-bottom": "1rem" }}>
                <CardHeader
                    title="No SBOM ingested"
                    count={props.coverage.unknown}
                    actions={
                        <Show when={ingestable().length > 0}>
                            <button
                                class="btn btn-sm btn-primary"
                                disabled={ingest.isPending}
                                onClick={() => runIngest(undefined)}
                            >
                                {ingest.isPending
                                    ? "Queueing…"
                                    : `Ingest ${plural(ingestable().length, "image")}`}
                            </button>
                        </Show>
                    }
                />
                <p class="text-muted">
                    These images report a registry-addressable digest that matches nothing in the
                    catalog. Ingesting the image is what closes this gap.
                    <Show when={(images.data?.data.length ?? 0) > 0}>
                        {" "}
                        {ingestable().length.toLocaleString()} of{" "}
                        {plural(images.data?.data.length ?? 0, "image")} can be ingested with the
                        registries this namespace already has.
                    </Show>
                </p>
                <Show when={ingest.data}>
                    {(res) => <p class="text-muted">{ingestSummary(res())}</p>}
                </Show>
                <Show when={ingest.error}>
                    {(err) => <p class="text-muted">Could not queue scans: {err().message}</p>}
                </Show>
                <DataTable
                    columns={unknownImageColumns((d) => runIngest([d]), pendingDigest)}
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
