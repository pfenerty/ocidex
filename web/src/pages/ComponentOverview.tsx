import { Show, For, createMemo } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useComponentVersions } from "~/api/queries";
import type { ComponentVersionEntry } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import PurlLink from "~/components/PurlLink";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import {
    relativeDate,
    formatDateTime,
    plural,
    shortDigest,
} from "~/utils/format";

interface VersionGroup {
    version: string;
    purl?: string;
    entries: ComponentVersionEntry[];
}

export default function ComponentOverview() {
    const [params] = useSearchParams<{ name: string; group?: string }>();

    const query = useComponentVersions(
        () =>
            params.name
                ? {
                      name: params.name,
                      group: params.group || undefined,
                  }
                : undefined,
        { enabled: () => !!params.name },
    );

    const displayName = () => {
        if (!params.name) return "Unknown";
        return params.group ? `${params.group}/${params.name}` : params.name;
    };

    const grouped = createMemo<VersionGroup[]>(() => {
        const versions = query.data?.versions;
        if (!versions || versions.length === 0) return [];

        const map = new Map<string, VersionGroup>();
        for (const entry of versions) {
            const key = entry.version ?? "(no version)";
            let group = map.get(key);
            if (!group) {
                group = { version: key, purl: entry.purl, entries: [] };
                map.set(key, group);
            }
            group.entries.push(entry);
        }
        return Array.from(map.values());
    });

    const componentType = () => query.data?.versions[0]?.type ?? "library";

    const firstPurl = () => {
        const versions = query.data?.versions;
        if (!versions) return undefined;
        return versions.find((v) => v.purl)?.purl;
    };

    return (
        <>
            <div class="breadcrumb">
                <A href="/components">Components</A>
                <span class="separator">/</span>
                <span>{displayName()}</span>
            </div>

            <Show when={!params.name}>
                <EmptyState
                    title="No component specified"
                    message="Navigate here from the components search page."
                />
            </Show>

            <Show when={params.name}>
                <Show when={!query.isLoading} fallback={<Loading />}>
                    <Show
                        when={!query.isError}
                        fallback={<ErrorBox error={query.error} />}
                    >
                        <Show
                            when={query.data && query.data.versions.length > 0}
                            fallback={
                                <EmptyState
                                    title="No versions found"
                                    message={`No component instances found for "${displayName()}".`}
                                />
                            }
                        >
                            <div class="page-header">
                                <div class="page-header-row">
                                    <div>
                                        <h2>{displayName()}</h2>
                                        <p class="text-muted">
                                            <span class="badge">
                                                {componentType()}
                                            </span>{" "}
                                            {plural(
                                                grouped().length,
                                                "version",
                                            )}{" "}
                                            across{" "}
                                            {plural(
                                                query.data!.versions.length,
                                                "SBOM",
                                            )}
                                        </p>
                                    </div>
                                    <div class="btn-group">
                                        <Show
                                            when={
                                                firstPurl() &&
                                                purlToRegistryUrl(firstPurl()!)
                                            }
                                        >
                                            <a
                                                href={
                                                    purlToRegistryUrl(
                                                        firstPurl()!,
                                                    )!
                                                }
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                class="btn btn-sm btn-primary"
                                            >
                                                View on{" "}
                                                {purlTypeLabel(firstPurl()!) ??
                                                    "Registry"}
                                            </a>
                                        </Show>
                                    </div>
                                </div>
                            </div>

                            <For each={grouped()}>
                                {(group) => (
                                    <div class="card mb-md">
                                        <div class="card-header">
                                            <h3>
                                                <A
                                                    href={`/components/${group.entries[0].id}`}
                                                    class="mono"
                                                >
                                                    {group.version}
                                                </A>
                                            </h3>
                                            <div class="btn-group">
                                                <Show when={group.purl}>
                                                    <PurlLink
                                                        purl={group.purl!}
                                                        showBadge
                                                    />
                                                </Show>
                                                <span class="badge">
                                                    {plural(
                                                        group.entries.length,
                                                        "SBOM",
                                                    )}
                                                </span>
                                            </div>
                                        </div>
                                        <div class="table-wrapper">
                                            <table>
                                                <thead>
                                                    <tr>
                                                        <th>Artifact</th>
                                                        <th>Digest</th>
                                                        <th>Ingested</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <For each={group.entries}>
                                                        {(entry) => (
                                                            <tr>
                                                                <td>
                                                                    <Show
                                                                        when={
                                                                            entry.artifactId
                                                                        }
                                                                        fallback={
                                                                            <A
                                                                                href={`/sboms/${entry.sbomId}`}
                                                                            >
                                                                                {entry.subjectVersion ??
                                                                                    formatDateTime(
                                                                                        entry.sbomCreatedAt,
                                                                                    )}
                                                                            </A>
                                                                        }
                                                                    >
                                                                        <A
                                                                            href={`/artifacts/${entry.artifactId}`}
                                                                        >
                                                                            {entry.artifactName ??
                                                                                entry.artifactId!.slice(
                                                                                    0,
                                                                                    8,
                                                                                )}
                                                                        </A>
                                                                        <Show
                                                                            when={
                                                                                entry.subjectVersion
                                                                            }
                                                                        >
                                                                            <span class="text-muted">
                                                                                :
                                                                                {
                                                                                    entry.subjectVersion
                                                                                }
                                                                            </span>
                                                                        </Show>
                                                                    </Show>
                                                                </td>
                                                                <td>
                                                                    <Show
                                                                        when={
                                                                            entry.sbomDigest
                                                                        }
                                                                        fallback={
                                                                            <span class="text-muted">
                                                                                —
                                                                            </span>
                                                                        }
                                                                    >
                                                                        <span
                                                                            class="mono text-sm"
                                                                            title={
                                                                                entry.sbomDigest
                                                                            }
                                                                        >
                                                                            {shortDigest(
                                                                                entry.sbomDigest!,
                                                                            )}
                                                                        </span>
                                                                    </Show>
                                                                </td>
                                                                <td
                                                                    class="nowrap text-muted"
                                                                    title={new Date(
                                                                        entry.sbomCreatedAt,
                                                                    ).toLocaleString()}
                                                                >
                                                                    {relativeDate(
                                                                        entry.sbomCreatedAt,
                                                                    )}
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </For>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}
                            </For>
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
