import { Show, createMemo, createSignal, createEffect, on } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { Breadcrumb, Button, ButtonGroup, PageHeader, QueryBoundary, type Crumb } from "~/components/ui";
import { useComponent, useComponentVersions, useComponentVersionSummaries, useComponentVulns } from "~/api/queries";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { SkeletonHeader } from "~/components/Skeleton";
import ComponentMetadata from "~/components/ComponentMetadata";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { plural, hasText } from "~/utils/format";
import { groupByArtifact, type ArtifactGroup } from "./grouping";
import { ArtifactUsageTable } from "./ArtifactUsageTable";
import { VersionListTable } from "./VersionListTable";

export default function ComponentOverview() {
    const [params] = useSearchParams<{ name: string; group?: string; version?: string }>();
    const [offset, setOffset] = createSignal(0);

    const hasVersion = () => params.version !== undefined && params.version !== "";

    // With a version pinned the page lists that version's SBOM occurrences;
    // without one it lists distinct versions, paged by version. Paging the
    // occurrences and grouping them by version showed one or two versions a
    // page of stdlib's 81 (ocidex-nps9.2).
    const query = useComponentVersions(
        () =>
            params.name !== undefined
                ? {
                      name: params.name,
                      group: params.group !== "" ? params.group : undefined,
                      version: params.version !== "" ? params.version : undefined,
                      limit: DEFAULT_PAGE_SIZE,
                      offset: offset(),
                  }
                : undefined,
        { enabled: () => params.name !== undefined && hasVersion() },
    );

    const summaryQuery = useComponentVersionSummaries(
        () =>
            params.name !== undefined
                ? {
                      name: params.name,
                      group: params.group !== "" ? params.group : undefined,
                      limit: DEFAULT_PAGE_SIZE,
                      offset: offset(),
                  }
                : undefined,
        { enabled: () => params.name !== undefined && !hasVersion() },
    );

    /** activeQuery is whichever of the two the page is showing. */
    const activeQuery = {
        get isLoading() {
            return hasVersion() ? query.isLoading : summaryQuery.isLoading;
        },
        get isError() {
            return hasVersion() ? query.isError : summaryQuery.isError;
        },
        get error() {
            return hasVersion() ? query.error : summaryQuery.error;
        },
        get data() {
            return hasVersion() ? query.data : summaryQuery.data;
        },
    };

    // A different component (or a drill-down into one version) is a different
    // result set, so the window has to go back to the top.
    createEffect(
        on(
            () => [params.name, params.group, params.version],
            () => setOffset(0),
            { defer: true },
        ),
    );

    const pagination = () => activeQuery.data?.pagination;

    const firstVersionId = () => query.data?.versions[0]?.id ?? "";
    const firstVersionPurl = () =>
        query.data?.versions.find((v) => v.purl !== undefined && v.purl !== "")?.purl ?? "";

    const detailQuery = useComponent(
        () => firstVersionId(),
        { enabled: () => hasVersion() && firstVersionId() !== "" },
    );

    const vulnsQuery = useComponentVulns(() => firstVersionId(), {
        enabled: () => hasVersion() && firstVersionId() !== "" && hasText(firstVersionPurl()),
    });

    const displayName = () => {
        if (params.name === undefined) return "Unknown";
        return params.group !== undefined && params.group !== ""
            ? `${params.group}/${params.name}`
            : params.name;
    };

    const artifactGroups = createMemo<ArtifactGroup[]>(() =>
        hasVersion() ? groupByArtifact(query.data?.versions ?? []) : [],
    );

    const componentType = () => activeQuery.data?.versions[0]?.type ?? "library";

    const totalRows = () => pagination()?.total ?? activeQuery.data?.versions.length ?? 0;
    // One page of results needs no controls and no "on this page" hedging.
    const isPaged = () => totalRows() > DEFAULT_PAGE_SIZE;

    const firstPurl = () => activeQuery.data?.versions.find((v) => v.purl !== undefined)?.purl;

    const allVersionsHref = () => {
        const base = `/components/overview?name=${encodeURIComponent(params.name ?? "")}`;
        const group =
            params.group !== undefined && params.group !== ""
                ? `&group=${encodeURIComponent(params.group)}`
                : "";
        return `${base}${group}`;
    };

    const versionHref = (version: string) =>
        `${allVersionsHref()}&version=${encodeURIComponent(version)}`;

    /* With a version pinned the name becomes a link back to all of its
       versions; without one the name *is* this page. */
    const crumbs = (): Crumb[] =>
        hasVersion()
            ? [
                { label: "Components", href: "/components" },
                { label: displayName(), href: allVersionsHref() },
                { label: params.version, mono: true },
            ]
            : [
                { label: "Components", href: "/components" },
                { label: displayName() },
            ];

    return (
        <>
            <Show when={params.name === undefined}>
                <EmptyState
                    title="No component specified"
                    message="Navigate here from the components search page."
                />
            </Show>

            <Show when={params.name !== undefined}>
                <QueryBoundary
                    query={activeQuery}
                    breadcrumb={<Breadcrumb items={crumbs()} />}
                    loading={<SkeletonHeader />}
                    when={(d) => d.versions.length > 0}
                    empty={
                        <EmptyState
                            title="No versions found"
                            message={`No component instances found for "${displayName()}".`}
                        />
                    }
                >
                    {() => (
                                <>
                                <PageHeader
                                    breadcrumb={<Breadcrumb items={crumbs()} />}
                                    title={
                                        <Show when={hasVersion()} fallback={displayName()}>
                                            {displayName()}{" "}
                                            <span class="font-mono">{params.version}</span>
                                        </Show>
                                    }
                                    subtitle={
                                        <>
                                            <span class="badge">{componentType()}</span>{" "}
                                            {/* Without a version these are whole-corpus
                                                figures, the same ones the Components list
                                                shows. With one, the list is that version's
                                                SBOM occurrences, so the artifact count is
                                                qualified once there is more than a page. */}
                                            <Show
                                                when={hasVersion()}
                                                fallback={
                                                    <>
                                                        {plural(summaryQuery.data?.pagination.total ?? 0, "version")} in{" "}
                                                        {plural(summaryQuery.data?.sbomCount ?? 0, "SBOM")} ·{" "}
                                                        {plural(summaryQuery.data?.artifactCount ?? 0, "artifact")}
                                                    </>
                                                }
                                            >
                                                <Show
                                                    when={isPaged()}
                                                    fallback={plural(artifactGroups().length, "artifact")}
                                                >
                                                    {plural(artifactGroups().length, "artifact")} on this page
                                                    {" · "}
                                                    {plural(query.data?.sbomCount ?? totalRows(), "SBOM")} in total
                                                </Show>
                                            </Show>
                                        </>
                                    }
                                    actions={
                                        <ButtonGroup>
                                            <Show when={hasVersion()}>
                                                <Button as={A} href={allVersionsHref()} size="sm">
                                                    ← All versions
                                                </Button>
                                            </Show>
                                            <Show
                                                when={
                                                    firstPurl() !== undefined
                                                        ? (purlToRegistryUrl(firstPurl() ?? "") ?? undefined)
                                                        : undefined
                                                }
                                            >
                                                {(registryUrl) => (
                                                    <Button
                                                        as="a"
                                                        href={registryUrl()}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        size="sm"
                                                        variant="primary"
                                                    >
                                                        View on {purlTypeLabel(firstPurl() ?? "") ?? "Registry"}
                                                    </Button>
                                                )}
                                            </Show>
                                        </ButtonGroup>
                                    }
                                />

                                    {/* ── Drill-down: specific version selected ── */}
                                    <Show when={hasVersion()}>
                                        <ComponentMetadata
                                            detailQuery={detailQuery}
                                            vulnsQuery={vulnsQuery}
                                            showVulns={hasText(firstVersionPurl())}
                                        />
                                        <ArtifactUsageTable groups={artifactGroups()} />
                                    </Show>

                                    {/* ── Summary: compact version list ── */}
                                    <Show when={!hasVersion()}>
                                        <VersionListTable
                                            versions={summaryQuery.data?.versions ?? []}
                                            versionHref={versionHref}
                                        />
                                    </Show>

                                    <Show when={isPaged() ? pagination() : undefined}>
                                        {(p) => (
                                            <Pagination pagination={p()} onPageChange={setOffset} />
                                        )}
                                    </Show>
                                </>
                    )}
                </QueryBoundary>
            </Show>
        </>
    );
}
