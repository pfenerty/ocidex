import { Show, createMemo, createSignal, createEffect, on } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { Button, ButtonGroup, PageHeader } from "~/components/ui";
import { useComponent, useComponentVersions, useComponentVulns } from "~/api/queries";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { SkeletonHeader } from "~/components/Skeleton";
import ComponentMetadata from "~/components/ComponentMetadata";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { plural, hasText } from "~/utils/format";
import { groupByArtifact, groupByVersion, type ArtifactGroup, type VersionGroup } from "./grouping";
import { ArtifactUsageTable } from "./ArtifactUsageTable";
import { VersionListTable } from "./VersionListTable";

export default function ComponentOverview() {
    const [params] = useSearchParams<{ name: string; group?: string; version?: string }>();
    const [offset, setOffset] = createSignal(0);

    const hasVersion = () => params.version !== undefined && params.version !== "";

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
        { enabled: () => params.name !== undefined },
    );

    // A different component (or a drill-down into one version) is a different
    // result set, so the window has to go back to the top.
    createEffect(
        on(
            () => [params.name, params.group, params.version],
            () => setOffset(0),
            { defer: true },
        ),
    );

    const pagination = () => query.data?.pagination;

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

    // The two groupings are mutually exclusive: without a version the page is a
    // version list, with one it is the artifacts carrying that version.
    const grouped = createMemo<VersionGroup[]>(() =>
        hasVersion() ? [] : groupByVersion(query.data?.versions ?? []),
    );
    const artifactGroups = createMemo<ArtifactGroup[]>(() =>
        hasVersion() ? groupByArtifact(query.data?.versions ?? []) : [],
    );

    const componentType = () => query.data?.versions[0]?.type ?? "library";

    const totalRows = () => pagination()?.total ?? query.data?.versions.length ?? 0;
    // One page of results needs no controls and no "on this page" hedging.
    const isPaged = () => totalRows() > DEFAULT_PAGE_SIZE;

    const firstPurl = () => query.data?.versions.find((v) => v.purl !== undefined)?.purl;

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

    return (
        <>
            <div class="breadcrumb">
                <A href="/components">Components</A>
                <span class="separator">/</span>
                <Show when={hasVersion()} fallback={<span>{displayName()}</span>}>
                    <A href={allVersionsHref()}>{displayName()}</A>
                    <span class="separator">/</span>
                    <span class="font-mono">{params.version}</span>
                </Show>
            </div>

            <Show when={params.name === undefined}>
                <EmptyState
                    title="No component specified"
                    message="Navigate here from the components search page."
                />
            </Show>

            <Show when={params.name !== undefined}>
                <Show when={!query.isLoading} fallback={<SkeletonHeader />}>
                    <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                        <Show
                            when={
                                query.data !== undefined && query.data.versions.length > 0
                                    ? query.data
                                    : undefined
                            }
                            keyed
                            fallback={
                                <EmptyState
                                    title="No versions found"
                                    message={`No component instances found for "${displayName()}".`}
                                />
                            }
                        >
                            {(qd) => (
                                <>
                                <PageHeader
                                    title={
                                        <Show when={hasVersion()} fallback={displayName()}>
                                            {displayName()}{" "}
                                            <span class="font-mono">{params.version}</span>
                                        </Show>
                                    }
                                    subtitle={
                                        <>
                                            <span class="badge">{componentType()}</span>{" "}
                                            {/* These count the rows on screen, and the
                                                list is paginated, so they are qualified
                                                the moment there is more than one page.
                                                The total is SBOM occurrences, which is
                                                what the endpoint counts; distinct
                                                versions across all pages is not a figure
                                                the API reports, so it is never claimed. */}
                                            <Show
                                                when={hasVersion()}
                                                fallback={
                                                    <Show
                                                        when={isPaged()}
                                                        fallback={
                                                            <>
                                                                {plural(grouped().length, "version")} across{" "}
                                                                {plural(qd.versions.length, "SBOM")}
                                                            </>
                                                        }
                                                    >
                                                        {plural(grouped().length, "version")} on this page
                                                        {" · "}
                                                        {plural(totalRows(), "SBOM")} in total
                                                    </Show>
                                                }
                                            >
                                                <Show
                                                    when={isPaged()}
                                                    fallback={plural(artifactGroups().length, "artifact")}
                                                >
                                                    {plural(artifactGroups().length, "artifact")} on this page
                                                    {" · "}
                                                    {plural(totalRows(), "SBOM")} in total
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
                                        <VersionListTable groups={grouped()} versionHref={versionHref} />
                                    </Show>

                                    <Show when={isPaged() ? pagination() : undefined}>
                                        {(p) => (
                                            <Pagination pagination={p()} onPageChange={setOffset} />
                                        )}
                                    </Show>
                                </>
                            )}
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
