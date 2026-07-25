import { Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useComponent, useComponentVulns } from "~/api/queries";
import { ErrorBox } from "~/components/Feedback";
import { Skeleton, SkeletonHeader } from "~/components/Skeleton";
import ComponentMetadata from "~/components/ComponentMetadata";
import { VulnCountBadges } from "~/components/VulnBadge";
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

    return (
        <>
            <div class="breadcrumb">
                <A href="/components">Components</A>
                <span class="separator">/</span>
                <span>
                    {detailQuery.data?.name ?? (
                        <Skeleton width="6rem" style={{ display: "inline-block" }} />
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
                            <div class="page-header">
                                <div class="page-header-row">
                                    <div>
                                        <h2
                                            style={{
                                                display: "flex",
                                                "align-items": "center",
                                                gap: "0.6rem",
                                                "flex-wrap": "wrap",
                                            }}
                                        >
                                            {detail.name}
                                            <Show when={hasText(detail.version)}>
                                                <span class="font-mono">{detail.version}</span>
                                            </Show>
                                        </h2>
                                        <p class="text-muted">
                                            <span class="badge">{detail.type}</span>{" "}
                                            <VulnCountBadges
                                                criticalCount={detail.criticalCount}
                                                highCount={detail.highCount}
                                                mediumCount={detail.mediumCount}
                                                lowCount={detail.lowCount}
                                                unknownCount={detail.unknownCount}
                                            />
                                        </p>
                                    </div>
                                    <div class="btn-group">
                                        <A
                                            href={`/sboms/${detail.sbomId}`}
                                            class="btn btn-sm btn-primary"
                                        >
                                            View SBOM
                                        </A>
                                    </div>
                                </div>
                            </div>

                            <ComponentMetadata
                                detailQuery={detailQuery}
                                vulnsQuery={vulnsQuery}
                                showVulns={hasText(detail.purl)}
                            />
                        </>
                    )}
                </Show>
            </Show>
        </>
    );
}
