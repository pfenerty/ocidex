import { Show, createMemo } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useComponent, useComponentVersions, useComponentVulns } from "~/api/queries";
import { ErrorBox, EmptyState } from "~/components/Feedback";
import { SkeletonHeader } from "~/components/Skeleton";
import ComponentMetadata from "~/components/ComponentMetadata";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { plural, hasText } from "~/utils/format";
import { groupByArtifact, groupByVersion, type ArtifactGroup, type VersionGroup } from "./grouping";
import { ArtifactUsageTable } from "./ArtifactUsageTable";
import { VersionListTable } from "./VersionListTable";

export default function ComponentOverview() {
    const [params] = useSearchParams<{ name: string; group?: string; version?: string }>();

    const hasVersion = () => params.version !== undefined && params.version !== "";

    const query = useComponentVersions(
        () =>
            params.name !== undefined
                ? {
                      name: params.name,
                      group: params.group !== "" ? params.group : undefined,
                      version: params.version !== "" ? params.version : undefined,
                  }
                : undefined,
        { enabled: () => params.name !== undefined },
    );

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
                                    <div class="page-header">
                                        <div class="page-header-row">
                                            <div>
                                                <h2>
                                                    <Show when={hasVersion()} fallback={displayName()}>
                                                        {displayName()}{" "}
                                                        <span class="font-mono">{params.version}</span>
                                                    </Show>
                                                </h2>
                                                <p class="text-muted">
                                                    <span class="badge">{componentType()}</span>{" "}
                                                    <Show
                                                        when={hasVersion()}
                                                        fallback={
                                                            <>
                                                                {plural(grouped().length, "version")} across{" "}
                                                                {plural(qd.versions.length, "SBOM")}
                                                            </>
                                                        }
                                                    >
                                                        {plural(artifactGroups().length, "artifact")}
                                                    </Show>
                                                </p>
                                            </div>
                                            <div class="btn-group">
                                                <Show when={hasVersion()}>
                                                    <A href={allVersionsHref()} class="btn btn-sm btn-secondary">
                                                        ← All versions
                                                    </A>
                                                </Show>
                                                <Show
                                                    when={
                                                        firstPurl() !== undefined
                                                            ? (purlToRegistryUrl(firstPurl() ?? "") ?? undefined)
                                                            : undefined
                                                    }
                                                >
                                                    {(registryUrl) => (
                                                        <a
                                                            href={registryUrl()}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            class="btn btn-sm btn-primary"
                                                        >
                                                            View on {purlTypeLabel(firstPurl() ?? "") ?? "Registry"}
                                                        </a>
                                                    )}
                                                </Show>
                                            </div>
                                        </div>
                                    </div>

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
                                </>
                            )}
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
