import "~/components/DetailSection.css";
import { Show, createMemo, createSignal } from "solid-js";
import { A, useParams, useNavigate, useSearchParams } from "@solidjs/router";
import { Breadcrumb, Button, ButtonGroup, Card, CardHeader, PageHeader, QueryBoundary, TabBar, createExpandedSet, type Crumb } from "~/components/ui";
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
import type { SortDir } from "~/components/DataTable";
import type { VulnSeverityFilter } from "~/api/queries";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { parsePurl } from "~/utils/purl";
import { artifactDisplayName, formatDateTime } from "~/utils/format";
import { PackagesTab } from "./PackagesTab";
import { VulnerabilitiesTab, SEVERITIES, SORT_KEYS as VULN_SORT_KEYS } from "./VulnerabilitiesTab";
import type { SBOMVulnSortKey } from "~/api/queries";

const TABS: SbomTab[] = ["packages", "provenance", "image", "git", "vulns", "raw"];

/** Search params arrive as string | string[]; take the first value either way. */
function one(v: string | string[] | undefined): string | undefined {
    return Array.isArray(v) ? v[0] : v;
}

export default function SBOMDetail() {
    const params = useParams<{ id: string }>();
    const navigate = useNavigate();
    const [searchParams, setSearchParams] = useSearchParams();

    /* The tab used to be component state, which made every view of this page the
       same URL. It lives in a search param now so the vulnerabilities tab's own
       filter and sort are linkable — "the criticals in this image, worst first"
       is the thing someone wants to paste into an issue. */
    const tab = (): SbomTab => {
        const t = one(searchParams.tab);
        return TABS.find((candidate) => candidate === t) ?? "packages";
    };
    // Switching tabs drops the vuln list's filter/sort/page: they mean nothing
    // to the other tabs and would otherwise reappear on the way back.
    const setTab = (next: SbomTab) =>
        setSearchParams({
            tab: next === "packages" ? undefined : next,
            severity: undefined,
            sort: undefined,
            dir: undefined,
            offset: undefined,
        });

    /* Tree or list for the packages tab. This is a search param and not a
       signal inside PackagesTab because QueryBoundary renders its child under
       <Show ... keyed>: a sort produces a new query result object, the subtree
       remounts, and any local state in it is gone. Sorting a column therefore
       used to throw the reader back into the tree view. Unlike the vuln
       filters above it is deliberately *not* cleared by setTab — it is a way of
       looking at the packages, not a narrowing of them, so leaving the tab and
       coming back should not undo it. */
    const pkgView = (): "tree" | "list" =>
        one(searchParams.view) === "list" ? "list" : "tree";
    const setPkgView = (next: "tree" | "list") =>
        setSearchParams({ view: next === "tree" ? undefined : next });

    // A hand-edited URL can say anything; an unrecognised value is dropped
    // rather than forwarded, so the list shows everything instead of nothing.
    const vulnSeverity = (): VulnSeverityFilter | undefined => {
        const raw = one(searchParams.severity);
        return SEVERITIES.find((candidate) => candidate === raw);
    };
    const vulnSortBy = (): SBOMVulnSortKey => {
        const raw = one(searchParams.sort);
        return VULN_SORT_KEYS.find((candidate) => candidate === raw) ?? "severity";
    };
    // Severity's useful default is worst-first, the opposite of what every
    // other column wants.
    const vulnSortDir = (): SortDir => {
        const raw = one(searchParams.dir);
        if (raw === "asc" || raw === "desc") return raw;
        return vulnSortBy() === "canonical_id" ? "asc" : "desc";
    };
    const vulnOffset = () => {
        const parsed = Number(one(searchParams.offset));
        return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    };
    const vulnExpanded = createExpandedSet();

    const artifactLookup = useArtifactNames();
    const artifactLabel = (id: string | undefined) => {
        const a = artifactLookup(id);
        return a ? artifactDisplayName(a) : undefined;
    };

    const sbomQuery = useSBOM(() => params.id);
    // Package-list sort lives here, not in PackagesTab, because it is a
    // parameter of the paged query rather than a reordering of what is loaded:
    // "worst first" has to be decided over the whole SBOM before the first page
    // is cut, not over the 200 rows that happen to be on screen.
    const [pkgSort, setPkgSort] = createSignal<"severity" | undefined>(undefined);
    const [pkgSortDir, setPkgSortDir] = createSignal<SortDir>("desc");
    const componentsQuery = useSBOMComponents(
        () => params.id,
        () => ({ sort: pkgSort(), dir: pkgSort() ? pkgSortDir() : undefined }),
    );
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

                            {/* --- Tabs --- */}
                            <TabBar
                                tabs={[
                                    { id: "packages", label: `Packages (${s.packageCount})` },
                                    { id: "provenance", label: "Provenance" },
                                    { id: "image", label: "Image" },
                                    { id: "git", label: "Git" },
                                    { id: "vulns", label: `Vulnerabilities (${s.vulnSummary?.total ?? 0})` },
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
                                            viewMode={pkgView()}
                                            onViewMode={setPkgView}
                                            sortBy={pkgSort()}
                                            sortDir={pkgSortDir()}
                                            onSort={(key, dir) => {
                                                setPkgSort(key === "severity" ? "severity" : undefined);
                                                setPkgSortDir(dir);
                                            }}
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

                            {/* --- Vulnerabilities tab --- */}
                            <Show when={tab() === "vulns"}>
                                <VulnerabilitiesTab
                                    sbomId={s.id}
                                    summary={s.vulnSummary}
                                    severity={vulnSeverity()}
                                    sortBy={vulnSortBy()}
                                    sortDir={vulnSortDir()}
                                    offset={vulnOffset()}
                                    expanded={vulnExpanded}
                                    onSeverityChange={(value) =>
                                        setSearchParams({ severity: value, offset: undefined })
                                    }
                                    onSort={(key, dir) =>
                                        setSearchParams({ sort: key, dir, offset: undefined })
                                    }
                                    onPageChange={(next) =>
                                        setSearchParams({ offset: next === 0 ? undefined : next })
                                    }
                                />
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
