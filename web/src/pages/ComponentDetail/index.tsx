import { Show, createSignal } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { Button, ButtonGroup, PageHeader } from "~/components/ui";
import { useComponent, useComponentVersions, useComponentVulns } from "~/api/queries";
import { ErrorBox } from "~/components/Feedback";
import { Skeleton, SkeletonHeader } from "~/components/Skeleton";
import type { ComponentDetail, VulnSummary } from "~/api/client";
import ComponentMetadata from "~/components/ComponentMetadata";
import type { ComponentTab } from "~/components/ComponentMetadata";
import { ComponentBand, type CorpusCounts } from "./ComponentBand";
import { hasText } from "~/utils/format";

/**
 * ComponentDetail renders a single component instance by its database id,
 * reached via /components/:id (from license and diff-tree links). The full
 * metadata rendering is shared with ComponentOverview's drill-down view.
 */
export default function ComponentDetail() {
    const params = useParams<{ id: string }>();

    const detailQuery = useComponent(() => params.id);
    // Vulnerability matching is purl-based, so only fetch/show vulns once we
    // know the component has a purl.
    const vulnsQuery = useComponentVulns(() => params.id, {
        enabled: () => hasText(detailQuery.data?.purl),
    });

    // "Where else does this live" is a question about the corpus, and a
    // component row is scoped to one SBOM — so the two figures come from the
    // versions endpoint, which reports them for the whole result set rather
    // than for a page. limit: 1 because only the counts are wanted here; the
    // rows themselves are what /components/overview is for.
    const countsQuery = useComponentVersions(() => {
        const d = detailQuery.data;
        if (d === undefined) return undefined;
        return { name: d.name, group: d.group, type: d.type, limit: 1 };
    });

    const counts = (): CorpusCounts | undefined => {
        const q = countsQuery.data;
        if (q === undefined) return undefined;
        // The generated types mark all three of these required, so the compiler
        // cannot see the case a rolling deploy creates: this bundle served
        // against an API pod that predates them. Reading through an absent
        // `pagination` throws inside a render effect, and an error escaping an
        // effect flush leaves Solid with a queue it never drains — the whole
        // page stops updating, not just this tile. Counts that did not arrive
        // are the same "not known yet" as a query still in flight.
        const p = q as Partial<typeof q>;
        if (
            p.pagination === undefined ||
            p.artifactCount === undefined ||
            p.versionCount === undefined
        ) {
            return undefined;
        }
        return {
            artifactCount: p.artifactCount,
            versionCount: p.versionCount,
            sbomCount: p.pagination.total,
        };
    };

    // The band's vulnerability tile speaks VulnSummary, which is the same five
    // severity buckets the component detail already carries under other names.
    // Every count is optional on the wire; absent means the component carries
    // no finding of that severity, which is 0 — not "unknown". The tile's
    // "not scanned" state is reserved for a component with no purl to match on,
    // which is gated separately.
    const vulnSummary = (d: ComponentDetail): VulnSummary => ({
        critical: d.criticalCount ?? 0,
        high: d.highCount ?? 0,
        medium: d.mediumCount ?? 0,
        low: d.lowCount ?? 0,
        unknown: d.unknownCount ?? 0,
        total: d.vulnCount ?? 0,
    });

    const [tab, setTab] = createSignal<ComponentTab>("details");

    return (
        <>
            <div class="breadcrumb">
                <A href="/components">Components</A>
                <span class="separator">/</span>
                <span>
                    {detailQuery.data?.name ?? (
                        <Skeleton width="6rem" inline />
                    )}
                </span>
            </div>

            <Show when={!detailQuery.isLoading} fallback={<SkeletonHeader />}>
                <Show
                    when={
                        !detailQuery.isError && detailQuery.data !== undefined
                            ? detailQuery.data
                            : undefined
                    }
                    keyed
                    fallback={<ErrorBox error={detailQuery.error} />}
                >
                    {(detail) => (
                        <>
                            {/* --- Hero --- */}
                            <PageHeader
                                title={
                                    <span class="title-inline">
                                        {detail.name}
                                        <Show when={hasText(detail.version)}>
                                            <span class="font-mono">{detail.version}</span>
                                        </Show>
                                    </span>
                                }
                                // The severity badges moved into the band's
                                // vulnerability tile, where they sit beside the
                                // count rather than restating it in a second
                                // vocabulary two lines above.
                                subtitle={<span class="badge">{detail.type}</span>}
                                actions={
                                    <ButtonGroup>
                                        <Button
                                            as={A}
                                            href={`/sboms/${detail.sbomId}`}
                                            size="sm"
                                            variant="primary"
                                        >
                                            View SBOM
                                        </Button>
                                    </ButtonGroup>
                                }
                            />

                            <ComponentBand
                                detail={detail}
                                counts={counts()}
                                vulns={vulnSummary(detail)}
                                active={tab()}
                                onSelect={setTab}
                            />

                            <ComponentMetadata
                                detailQuery={detailQuery}
                                vulnsQuery={vulnsQuery}
                                showVulns={hasText(detail.purl)}
                                tab={tab()}
                                onTabChange={setTab}
                            />
                        </>
                    )}
                </Show>
            </Show>
        </>
    );
}
