import "~/components/DetailSection.css";
import { Show, createSignal, createMemo } from "solid-js";
import { A, useParams, useNavigate } from "@solidjs/router";
import { Breadcrumb, Button, ButtonGroup, Card, CardHeader, PageHeader, QueryBoundary, TabBar, type Crumb } from "~/components/ui";
import { useSBOM, useSBOMComponents, sbomComponents, useSBOMDependencies, useSBOMDriftHistory, useArtifactSBOMs } from "~/api/queries";
import { useArtifactNames } from "~/api/queries";
import type { OCIMetadata, Provenance, GitCommitMetadata } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import { Skeleton, SkeletonHeader, SkeletonTable } from "~/components/Skeleton";
import CopyDigest from "~/components/CopyDigest";
import CopyShareLink, { sbomLookupPath } from "~/components/CopyShareLink";
import ImageMetadataCard from "~/components/ImageMetadataCard";
import ProvenanceCard from "~/components/ProvenanceCard";
import GitCommitCard from "~/components/GitCommitCard";
import SummaryBand, { type SbomTab } from "~/components/SummaryBand";
import { VulnSummaryBar } from "~/components/VulnBadge";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { parsePurl } from "~/utils/purl";
import { artifactDisplayName, formatDateTime } from "~/utils/format";
import { PackagesTab } from "./PackagesTab";

export default function SBOMDetail() {
    const params = useParams<{ id: string }>();
    const navigate = useNavigate();
    const [tab, setTab] = createSignal<SbomTab>("packages");

    const artifactLookup = useArtifactNames();
    const artifactLabel = (id: string | undefined) => {
        const a = artifactLookup(id);
        return a ? artifactDisplayName(a) : undefined;
    };

    const sbomQuery = useSBOM(() => params.id);
    const componentsQuery = useSBOMComponents(() => params.id);
    const loadedComponents = () => sbomComponents(componentsQuery.data?.pages);
    const depsQuery = useSBOMDependencies(() => params.id);

    const siblingsQuery = useArtifactSBOMs(
        () => sbomQuery.data?.artifactId ?? "",
        () => ({ limit: 50, subject_version: sbomQuery.data?.subjectVersion }),
        { enabled: () => sbomQuery.data?.artifactId !== undefined && sbomQuery.data.subjectVersion !== undefined },
    );

    const archSiblings = () => {
        const seen = new Set<string>();
        return (siblingsQuery.data?.data ?? []).filter(s => {
            if (s.architecture === undefined) return false;
            if (seen.has(s.architecture)) return false;
            seen.add(s.architecture);
            return true;
        });
    };

    const provenance = () => sbomQuery.data?.enrichments?.provenance as Provenance | undefined;
    const driftHistoryQuery = useSBOMDriftHistory(
        () => params.id,
        () => ({ limit: 20 }),
        { enabled: () => provenance() !== undefined },
    );
    const metadata = () => sbomQuery.data?.enrichments?.["oci-metadata"] as OCIMetadata | undefined;
    const gitCommit = () => sbomQuery.data?.enrichments?.git as GitCommitMetadata | undefined;

    // Top package ecosystems (purl types) for the Packages summary tile.
    const ecosystems = createMemo(() => {
        const counts = new Map<string, number>();
        for (const c of loadedComponents()) {
            if (c.type === "file") continue;
            const t = parsePurl(c.purl ?? "")?.type ?? c.type;
            if (t === "") continue;
            counts.set(t, (counts.get(t) ?? 0) + 1);
        }
        return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(e => e[0]);
    });

    const title = () => {
        const s = sbomQuery.data;
        if (!s) return params.id;
        const name = artifactLabel(s.artifactId);
        if (name !== undefined && s.subjectVersion !== undefined && s.subjectVersion !== "") return `${name} @ ${s.subjectVersion}`;
        if (name !== undefined) return name;
        if (s.subjectVersion !== undefined && s.subjectVersion !== "") return s.subjectVersion;
        return "SBOM Detail";
    };

    const subtitle = () => {
        const s = sbomQuery.data;
        if (!s) return "";
        // No component count here. It counted every component including file
        // entries (4,193 on a typical image), so it sat directly above a tile
        // and a tab both reading the package count (958) with nothing to say
        // which was authoritative. The band owns the package figure now, and
        // the packages tab explains what it excludes.
        const parts: string[] = [`CycloneDX ${s.specVersion}`];
        parts.push(`Ingested ${formatDateTime(s.createdAt)}`);
        return parts.join(" · ");
    };

    /* The root crumb used to be `/sboms`, a route App.tsx does not declare — it
       rendered the 404 page. An SBOM's parent is the artifact it describes, so
       the trail walks that chain instead, which is also what makes the artifact
       reachable from here in one click. */
    const crumbs = (): Crumb[] => {
        const artifactId = sbomQuery.data?.artifactId;
        const leaf =
            sbomQuery.isLoading
                ? <Skeleton width="6rem" inline />
                : (sbomQuery.data?.subjectVersion ??
                    formatDateTime(sbomQuery.data?.createdAt ?? "")) || params.id;
        return [
            { label: "Artifacts", href: "/artifacts" },
            ...(artifactId !== undefined
                ? [{ label: artifactLabel(artifactId) ?? "Artifact", href: `/artifacts/${artifactId}` }]
                : []),
            { label: leaf },
        ];
    };

    return (
        <>
            {/* The old ladder rendered <ErrorBox> whenever the data was absent,
                so a successful response with no SBOM claimed "an unexpected
                error occurred". QueryBoundary keeps error and empty apart. */}
            <QueryBoundary
                query={sbomQuery}
                breadcrumb={<Breadcrumb items={crumbs()} />}
                loading={<SkeletonHeader />}
                empty={<EmptyState title="SBOM not found." message="This SBOM may have been deleted, or the link may be wrong." />}
            >
                {(sbom) => {
                    // Keyed on the resolved value, so reading it once here is
                    // the same binding the previous `<Show keyed>` gave.
                    const s = sbom();
                    return (
                        <>
                            {/* --- Hero --- */}
                            <PageHeader
                                breadcrumb={<Breadcrumb items={crumbs()} />}
                                title={
                                    <span class="title-inline">
                                        {title()}
                                        <Show when={trustStatus(s.signingStatus)}>
                                            {(t) => <span class={trustBadgeClass(t().variant)}>{t().label}</span>}
                                        </Show>
                                    </span>
                                }
                                subtitle={subtitle()}
                                meta={
                                    <Show when={s.digest} keyed>
                                        {(digest) => (
                                            <CopyDigest
                                                digest={digest}
                                                artifactName={artifactLookup(s.artifactId)?.name}
                                                class="text-sm"
                                            />
                                        )}
                                    </Show>
                                }
                                actions={
                                    <ButtonGroup>
                                        <Show when={s.artifactId}>
                                            <Button as={A} href={`/artifacts/${s.artifactId}`} size="sm">View Artifact</Button>
                                        </Show>
                                        <Show when={s.artifactId !== undefined && s.subjectVersion !== undefined}>
                                            <Button as={A} href={`/artifacts/${s.artifactId}/versions/${encodeURIComponent(s.subjectVersion ?? "")}`} size="sm">
                                                View build history
                                            </Button>
                                        </Show>
                                        <Button as={A} href={`/diff?from=${s.id}&to=${s.id}`} size="sm">Compare</Button>
                                        <Show when={sbomLookupPath(s)}>
                                            {(path) => <CopyShareLink path={path()} />}
                                        </Show>
                                    </ButtonGroup>
                                }
                            />

                            {/* --- Arch switcher --- */}
                            <Show when={archSiblings().length > 1}>
                                {/* A `nav` strip, not a filter: each sibling is
                                    a different SBOM at a different URL. */}
                                <TabBar
                                    tabs={archSiblings().map((sib) => ({
                                        id: sib.id,
                                        label: sib.architecture ?? sib.id,
                                    }))}
                                    active={params.id}
                                    onSelect={(id) => navigate(`/sboms/${id}`)}
                                    class="mb-sm"
                                />
                            </Show>

                            {/* --- Summary band --- */}
                            <SummaryBand
                                provenance={provenance()}
                                signingStatus={s.signingStatus}
                                metadata={metadata()}
                                git={gitCommit()}
                                packageCount={s.packageCount}
                                ecosystems={ecosystems()}
                                vulns={s.vulnSummary}
                                specVersion={s.specVersion}
                                ingestedAt={s.createdAt}
                                active={tab()}
                                onSelect={setTab}
                            />

                            {/* --- Vulnerability summary --- */}
                            <VulnSummaryBar summary={s.vulnSummary} />

                            {/* --- Tabs --- */}
                            <TabBar
                                tabs={[
                                    { id: "packages", label: `Packages (${s.packageCount})` },
                                    { id: "provenance", label: "Provenance" },
                                    { id: "image", label: "Image" },
                                    { id: "git", label: "Git" },
                                    { id: "raw", label: "Raw" },
                                ]}
                                active={tab()}
                                onSelect={setTab}
                            />

                            {/* --- Packages tab --- */}
                            <Show when={tab() === "packages"}>
                                <QueryBoundary
                                    query={componentsQuery}
                                    loading={<SkeletonTable columns={5} />}
                                >
                                    {() => (
                                        <PackagesTab
                                            components={loadedComponents()}
                                            depsGraph={(depsQuery.data?.edges.length ?? 0) > 0 ? depsQuery.data : undefined}
                                            hasMore={componentsQuery.hasNextPage}
                                            loadingMore={componentsQuery.isFetchingNextPage}
                                            onLoadMore={() => void componentsQuery.fetchNextPage()}
                                            totalCount={s.packageCount}
                                            componentCount={s.componentCount}
                                        />
                                    )}
                                </QueryBoundary>
                            </Show>

                            {/* --- Provenance tab --- */}
                            <Show when={tab() === "provenance"}>
                                <Show
                                    when={provenance()}
                                    keyed
                                    fallback={<EmptyState title="No provenance data" message="No cosign signature or SLSA attestation was found for this image. Provenance enrichment runs after ingestion." />}
                                >
                                    {(prov) => <ProvenanceCard provenance={prov} signingStatus={s.signingStatus} drift={sbomQuery.data?.provenanceDrift} driftHistory={driftHistoryQuery.data?.data} />}
                                </Show>
                            </Show>

                            {/* --- Image tab --- */}
                            <Show when={tab() === "image"}>
                                <Show
                                    when={metadata()}
                                    keyed
                                    fallback={<EmptyState title="No image metadata" message="No OCI image metadata enrichment is available for this SBOM yet." />}
                                >
                                    {(m) => <ImageMetadataCard metadata={m} ingestedAt={s.createdAt} />}
                                </Show>
                            </Show>

                            {/* --- Git tab --- */}
                            <Show when={tab() === "git"}>
                                <Show
                                    when={gitCommit()?.resolved === true ? gitCommit() : undefined}
                                    fallback={
                                        <EmptyState
                                            title="No git commit data"
                                            message={
                                                gitCommit()?.reason !== undefined && gitCommit()?.reason !== ""
                                                    ? `Git enrichment could not resolve a commit: ${gitCommit()?.reason}.`
                                                    : "No git commit enrichment is available for this SBOM yet."
                                            }
                                        />
                                    }
                                >
                                    {(commit) => <GitCommitCard commit={commit()} />}
                                </Show>
                            </Show>

                            {/* --- Raw tab (identity + CycloneDX internals) --- */}
                            <Show when={tab() === "raw"}>
                                <Card class="mb-4">
                                    <CardHeader title="SBOM details" />
                                    <div class="detail-grid">
                                        <Show when={s.artifactId}>
                                            <div class="detail-field">
                                                <span class="detail-label">Artifact</span>
                                                <span class="detail-value">
                                                    <A href={`/artifacts/${s.artifactId}`}>{artifactLabel(s.artifactId) ?? s.artifactId}</A>
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={s.subjectVersion}>
                                            <div class="detail-field">
                                                <span class="detail-label">Version</span>
                                                <span class="detail-value">{s.subjectVersion}</span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">Spec Version</span>
                                            <span class="detail-value">CycloneDX {s.specVersion}</span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">BOM Version</span>
                                            <span class="detail-value">{s.version}</span>
                                        </div>
                                        <Show when={s.serialNumber}>
                                            <div class="detail-field">
                                                <span class="detail-label">Serial Number</span>
                                                <span class="detail-value font-mono text-sm">{s.serialNumber}</span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">Internal ID</span>
                                            <span class="detail-value font-mono text-sm">{s.id}</span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">Ingested</span>
                                            <span class="detail-value">{formatDateTime(s.createdAt)}</span>
                                        </div>
                                        <Show when={s.digest} keyed>
                                            {(digest) => (
                                                <div class="detail-field">
                                                    <span class="detail-label">Image Digest</span>
                                                    <CopyDigest digest={digest} artifactName={artifactLookup(s.artifactId)?.name} full class="detail-value" />
                                                </div>
                                            )}
                                        </Show>
                                    </div>
                                </Card>
                            </Show>
                        </>
                    );
                }}
            </QueryBoundary>
        </>
    );
}
