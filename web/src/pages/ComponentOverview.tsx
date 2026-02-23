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
                                {(group) => {
                                    const hasArch = () => group.entries.some(e => e.architecture != null);
                                    const archGroups = () => {
                                        if (!hasArch()) return null;
                                        const order: string[] = [];
                                        const map = new Map<string, ComponentVersionEntry[]>();
                                        for (const e of group.entries) {
                                            const key = e.subjectVersion ?? e.sbomId;
                                            if (!map.has(key)) { order.push(key); map.set(key, []); }
                                            map.get(key)!.push(e);
                                        }
                                        return { order, map };
                                    };
                                    return (
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
                                            <Show
                                                when={hasArch()}
                                                fallback={
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
                                                                                when={entry.artifactId}
                                                                                fallback={
                                                                                    <A href={`/sboms/${entry.sbomId}`}>
                                                                                        {entry.subjectVersion ?? formatDateTime(entry.sbomCreatedAt)}
                                                                                    </A>
                                                                                }
                                                                            >
                                                                                <A href={`/artifacts/${entry.artifactId}`}>
                                                                                    {entry.artifactName ?? entry.artifactId!.slice(0, 8)}
                                                                                </A>
                                                                                <Show when={entry.subjectVersion}>
                                                                                    <span class="text-muted">:{entry.subjectVersion}</span>
                                                                                </Show>
                                                                            </Show>
                                                                        </td>
                                                                        <td>
                                                                            <Show
                                                                                when={entry.sbomDigest}
                                                                                fallback={<span class="text-muted">—</span>}
                                                                            >
                                                                                <span class="mono text-sm" title={entry.sbomDigest}>
                                                                                    {shortDigest(entry.sbomDigest!)}
                                                                                </span>
                                                                            </Show>
                                                                        </td>
                                                                        <td
                                                                            class="nowrap text-muted"
                                                                            title={new Date(entry.sbomCreatedAt).toLocaleString()}
                                                                        >
                                                                            {relativeDate(entry.sbomCreatedAt)}
                                                                        </td>
                                                                    </tr>
                                                                )}
                                                            </For>
                                                        </tbody>
                                                    </table>
                                                }
                                            >
                                                <table>
                                                    <thead>
                                                        <tr>
                                                            <th>Artifact</th>
                                                            <th>Architectures</th>
                                                            <th>Ingested</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <For each={archGroups()!.order}>
                                                            {(key) => {
                                                                const entries = archGroups()!.map.get(key)!;
                                                                const preferred = entries.find(e => e.architecture === "amd64") ?? entries[0];
                                                                return (
                                                                    <>
                                                                        <tr style={{ "font-weight": "600" }}>
                                                                            <td>
                                                                                <Show
                                                                                    when={preferred.artifactId}
                                                                                    fallback={
                                                                                        <A href={`/sboms/${preferred.sbomId}`}>
                                                                                            {preferred.subjectVersion ?? formatDateTime(preferred.sbomCreatedAt)}
                                                                                        </A>
                                                                                    }
                                                                                >
                                                                                    <A href={`/artifacts/${preferred.artifactId}`}>
                                                                                        {preferred.artifactName ?? preferred.artifactId!.slice(0, 8)}
                                                                                    </A>
                                                                                    <Show when={preferred.subjectVersion}>
                                                                                        <span class="text-muted">:{preferred.subjectVersion}</span>
                                                                                    </Show>
                                                                                </Show>
                                                                            </td>
                                                                            <td>
                                                                                <For each={entries}>
                                                                                    {(e) => (
                                                                                        <span class="badge badge-primary" style={{ "margin-right": "4px" }}>
                                                                                            {e.architecture}
                                                                                        </span>
                                                                                    )}
                                                                                </For>
                                                                            </td>
                                                                            <td
                                                                                class="nowrap text-muted"
                                                                                title={new Date(preferred.sbomCreatedAt).toLocaleString()}
                                                                            >
                                                                                {relativeDate(preferred.sbomCreatedAt)}
                                                                            </td>
                                                                        </tr>
                                                                        <For each={entries}>
                                                                            {(e) => (
                                                                                <tr style={{ background: "var(--color-bg-alt, #f8f9fa)" }}>
                                                                                    <td style={{ "padding-left": "2rem" }} colspan={3}>
                                                                                        <span class="badge badge-primary" style={{ "margin-right": "8px" }}>
                                                                                            {e.architecture}
                                                                                        </span>
                                                                                        <A href={`/sboms/${e.sbomId}`} style={{ "margin-right": "12px" }}>
                                                                                            SBOM
                                                                                        </A>
                                                                                        <Show when={e.sbomDigest}>
                                                                                            <span class="mono text-sm text-muted" title={e.sbomDigest}>
                                                                                                {shortDigest(e.sbomDigest!)}
                                                                                            </span>
                                                                                        </Show>
                                                                                    </td>
                                                                                </tr>
                                                                            )}
                                                                        </For>
                                                                    </>
                                                                );
                                                            }}
                                                        </For>
                                                    </tbody>
                                                </table>
                                            </Show>
                                        </div>
                                    </div>
                                    );
                                }}
                            </For>
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
