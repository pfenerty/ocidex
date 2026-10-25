import { Show, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import { Button, Card, CardHeader, StatusPill } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { plural } from "~/utils/format";
import type {
    IngestReason,
    IngestResult,
    UnknownHost,
    UnknownImage,
    WorkloadCoverage,
} from "~/api/client";
import { useClusterWorkloads, useClusterUnknownImages, useIngestUnknown } from "~/api/queries";
import { ImageCell, workloadColumns } from "./WorkloadsTab";
import { RegistryGaps } from "./RegistryGaps";

/** Rows per page in both tables. Small enough that the pager is visible on the
 *  first screen, which is the point of having one. */
const PAGE_SIZE = 50;

/**
 * How each ingest reason is presented. Every one of them is a different thing
 * to do — add credentials, switch a registry on, fix the node — so a single
 * "cannot ingest" would send everyone to the wrong remedy.
 */
export const REASON_PRESENTATION: Record<
    IngestReason,
    { label: string; variant: "success" | "warning" | "danger" }
> = {
    ready: { label: "ready to ingest", variant: "success" },
    scanning: { label: "scanning", variant: "success" },
    unauthorized: { label: "pull refused", variant: "danger" },
    egress_denied: { label: "address refused", variant: "danger" },
    failed: { label: "scan failed", variant: "danger" },
    deleted: { label: "SBOM deleted", variant: "warning" },
    registry_disabled: { label: "registry disabled", variant: "warning" },
    unparseable_ref: { label: "no host in reference", variant: "warning" },
};

/**
 * The add-registry deep link.
 *
 * The rollup card sends every repository behind a host; a table row sends the
 * one it names. Both go through this function so a form opened from either
 * place is filled in the same way — a link that only named the host would leave
 * a ghcr.io or quay.io registry unusable, since neither supports catalog
 * discovery and both require the list.
 *
 * `ns` is the cluster's namespace. Registry resolution is namespace-local, and
 * a registry created without one gets a namespace of its own, so omitting it
 * yields a registry the cluster cannot see and a gap that does not close.
 *
 * `scope` is the group the server grouped by — the host on a single-tenant
 * registry, `ghcr.io/orgA` on a multi-tenant one. It names the registry; `host`
 * still addresses it.
 */
export function addRegistryHref(
    host: string,
    repos: string[],
    namespace: string,
    scope: string,
): string {
    const q = new URLSearchParams({ add: "1", host });
    if (repos.length > 0) q.set("repos", repos.join(","));
    if (namespace !== "") q.set("ns", namespace);
    if (scope !== "" && scope !== host) q.set("name", scope);
    return `/admin/sources?${q.toString()}`;
}

/**
 * scopeForImage finds the rollup group one table row belongs to.
 *
 * The row link and the card button must propose the same registry, and the
 * judgement about how deep a host's tenancy goes is the server's — duplicating
 * that table in TypeScript would give the two paths two chances to disagree.
 * So the row asks the rollup it was served alongside: the longest scope on the
 * same host that this image's path sits under. A row whose group is absent —
 * it cannot be, every grouped reason is rolled up — falls back to the host.
 */
export function scopeForImage(hosts: UnknownHost[], host: string, repository: string): string {
    const path = repository === "" ? host : `${host}/${repository}`;
    let best = host;
    for (const h of hosts) {
        if (h.host !== host || h.scope.length <= best.length) continue;
        if (path === h.scope || path.startsWith(`${h.scope}/`)) best = h.scope;
    }
    return best;
}

/** Reasons a click on the row's button can change: queue it, or ask again. */
const RETRYABLE: ReadonlySet<IngestReason> = new Set(["unauthorized", "egress_denied", "failed"]);

/**
 * IngestTargetCell says what stands between this image and an SBOM.
 *
 * The registry is named whenever one was matched at all: the one whose
 * credentials pull the image, or the disabled one blocking it. "ghcr is
 * disabled" is only actionable if you know it is ghcr.
 */
function IngestTargetCell(props: {
    image: UnknownImage;
    hosts: UnknownHost[];
    namespace: string;
    onIngest: (digest: string) => void;
    pending: boolean;
}) {
    const reason = () => REASON_PRESENTATION[props.image.reason];
    return (
        <div class="ingest-target">
            <StatusPill variant={reason().variant}>{reason().label}</StatusPill>
            <Show when={props.image.reason === "ready" || RETRYABLE.has(props.image.reason)}>
                <Button
                    size="sm"
                    disabled={props.pending}
                    onClick={() => props.onIngest(props.image.imageDigest)}
                >
                    {props.pending ? "Queueing…" : props.image.reason === "ready" ? "Ingest" : "Retry"}
                </Button>
            </Show>
            <Show when={props.image.reason === "ready" && props.image.registryId === undefined}>
                <span class="text-muted text-sm">anonymous pull</span>
            </Show>
            {/* Registries are managed on the Sources tab. These used to point at
                a top-level /registries route that has never existed, so both
                links 404'd — the tab tells a reader exactly what to fix and
                then sent them nowhere. */}
            <Show when={props.image.registryId}>
                {(id) => (
                    <A href={`/admin/sources?registry=${id()}`} class="text-sm">
                        {props.image.registryName ?? "registry"}
                    </A>
                )}
            </Show>
            <Show when={props.image.reason === "unauthorized"}>
                <span class="text-muted text-sm">
                    <span class="font-mono">{props.image.registryHost}</span> refused the pull —{" "}
                    <A
                        href={addRegistryHref(
                            props.image.registryHost ?? "",
                            props.image.repository === undefined || props.image.repository === ""
                                ? []
                                : [props.image.repository],
                            props.namespace,
                            scopeForImage(
                                props.hosts,
                                props.image.registryHost ?? "",
                                props.image.repository ?? "",
                            ),
                        )}
                    >
                        add a registry with credentials
                    </A>
                    , then retry
                </span>
            </Show>
            <Show when={props.image.reason === "egress_denied"}>
                <span class="text-muted text-sm">
                    <span class="font-mono">{props.image.registryHost}</span> resolves to an
                    address the egress policy refuses
                </span>
            </Show>
            <Show when={props.image.reason === "deleted"}>
                <span class="text-muted text-sm">
                    its SBOM was deleted on purpose; rescan it from the image's page
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
    hosts: () => UnknownHost[],
    namespace: string,
    onIngest: (digest: string) => void,
    pendingDigest: () => string | null,
): Column<UnknownImage>[] {
    return [
    {
        // The same cell the Workloads tab renders, rather than a second
        // rendering of the same fact: it mutes everything before the last path
        // segment, so a 60-character ref reads as its image name without the
        // host being hidden. `col-ref` caps the column — an image ref is one
        // unbreakable token, and uncapped it took the whole table.
        header: "Image",
        class: "col-ref",
        sortValue: (i) => i.imageRef,
        render: (i) => <ImageCell row={i} />,
    },
    {
        header: "Running as",
        class: "col-ref",
        render: (i) => (
            <>
                <span class="text-muted">{i.sampleK8sNamespace}/</span>
                {i.sampleWorkloadName}
                <Show when={i.workloadCount > 1}>
                    <span class="text-muted text-sm">
                        {" "}
                        and {plural(i.workloadCount - 1, "other container")}
                    </span>
                </Show>
            </>
        ),
    },
    {
        header: "Pods",
        align: "right",
        sortValue: (i) => i.podCount,
        render: (i) => i.podCount.toLocaleString(),
    },
    {
        header: "Ingest",
        class: "col-action",
        sortValue: (i) => i.reason,
        render: (i) => (
            <IngestTargetCell
                image={i}
                hosts={hosts()}
                namespace={namespace}
                onIngest={onIngest}
                pending={pendingDigest() === i.imageDigest}
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
        [res.skippedExisting, "already scanning, failed or deleted"],
        [res.unauthorized, "pull refused by the host"],
        [res.egressDenied, "address refused by the egress policy"],
        [res.skippedRegistryDisabled, "registry disabled"],
        [res.skippedUnparseableRef, "no host in the reference"],
        [res.failed, "submission failed"],
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
export function GapsTab(props: {
    clusterId: string;
    /**
     * The cluster's own namespace. It travels into every add-registry link
     * because resolution is namespace-local: a registry created anywhere else
     * closes nothing here.
     */
    namespace: string;
    coverage: WorkloadCoverage;
}) {
    // Both tables used to ask for 200 rows and render no pager, so a cluster
    // past that showed a short list with nothing saying it was short — the
    // quiet omission ADR-044 K5 exists to prevent. Offsets are local rather
    // than in the URL: this is a review workflow, and two more search params
    // for it would be the only state on the tab.
    const [imageOffset, setImageOffset] = createSignal(0);
    const [workloadOffset, setWorkloadOffset] = createSignal(0);

    const images = useClusterUnknownImages(
        () => props.clusterId,
        () => ({ limit: PAGE_SIZE, offset: imageOffset() }),
    );
    const unresolvable = useClusterWorkloads(
        () => props.clusterId,
        () => ({ matchState: "unresolvable" as const, limit: PAGE_SIZE, offset: workloadOffset() }),
    );

    // From the server's tally of the whole gap, not from the page in hand: the
    // bulk button ingests everything, so a count taken off one page would
    // understate what the click is about to do.
    const hosts = () => images.data?.hosts ?? [];
    const readyCount = () => images.data?.reasons.ready ?? 0;
    const gapTotal = () => images.data?.pagination.total ?? 0;

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
            {/* Above the image list, because the registry is the bigger unit of
                work: one registry closes every image behind its host, and a
                reader who fixes that first never has to read most of the rows
                below. */}
            <RegistryGaps hosts={hosts()} namespace={props.namespace} />

            <Card class="mb-4">
                <CardHeader
                    title="No SBOM ingested"
                    count={props.coverage.unknown}
                    actions={
                        <Show when={readyCount() > 0}>
                            <Button
                                size="sm"
                                variant="primary"
                                disabled={ingest.isPending}
                                onClick={() => runIngest(undefined)}
                            >
                                {ingest.isPending
                                    ? "Queueing…"
                                    : `Ingest ${plural(readyCount(), "image")}`}
                            </Button>
                        </Show>
                    }
                />
                <p class="text-muted">
                    These images report a registry-addressable digest that matches nothing in the
                    catalog. Ingesting the image is what closes this gap.
                    <Show when={gapTotal() > 0}>
                        {" "}
                        {readyCount().toLocaleString()} of {plural(gapTotal(), "image")} can be
                        ingested now, with this namespace's registries or anonymously.
                    </Show>
                </p>
                <Show when={ingest.data}>
                    {(res) => <p class="text-muted">{ingestSummary(res())}</p>}
                </Show>
                <Show when={ingest.error}>
                    {(err) => <p class="text-muted">Could not queue scans: {err().message}</p>}
                </Show>
                <DataTable
                    columns={unknownImageColumns(
                        hosts,
                        props.namespace,
                        (d) => runIngest([d]),
                        pendingDigest,
                    )}
                    rows={images.data?.data}
                    loading={images.isFetching}
                    isError={images.isError}
                    error={images.error}
                    pagination={
                        images.data
                            ? {
                                  pagination: images.data.pagination,
                                  onPageChange: setImageOffset,
                              }
                            : undefined
                    }
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
                    loading={unresolvable.isFetching}
                    isError={unresolvable.isError}
                    error={unresolvable.error}
                    pagination={
                        unresolvable.data
                            ? {
                                  pagination: unresolvable.data.pagination,
                                  onPageChange: setWorkloadOffset,
                              }
                            : undefined
                    }
                    emptyTitle="Every container reported a digest"
                    emptyMessage="No running container is unmatchable."
                />
            </Card>

            <Show when={props.coverage.unknown + props.coverage.unresolvable === 0}>
                <p class="text-muted mt-4">
                    All {plural(props.coverage.total, "running container")} matched an ingested
                    SBOM.
                </p>
            </Show>
        </>
    );
}
