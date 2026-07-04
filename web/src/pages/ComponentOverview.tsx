import { Show, For, createMemo } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useComponentVersions } from "~/api/queries";
import type { ComponentVersionEntry } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import CopyDigest from "~/components/CopyDigest";
import PurlLink from "~/components/PurlLink";
import { VulnCountBadges } from "~/components/VulnBadge";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { relativeDate, formatDateTime, plural } from "~/utils/format";

interface VersionGroup {
    version: string;
    purl?: string;
    entries: ComponentVersionEntry[];
}

export default function ComponentOverview() {
    const [params] = useSearchParams<{ name: string; group?: string; version?: string }>();

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

    const displayName = () => {
        if (params.name === undefined) return "Unknown";
        return params.group !== undefined && params.group !== ""
            ? `${params.group}/${params.name}`
            : params.name;
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
        return versions.find((v) => v.purl !== undefined)?.purl;
    };

    const hasVersion = () => params.version !== undefined && params.version !== "";

    const versionHref = (version: string) => {
        const base = `/components/overview?name=${encodeURIComponent(params.name ?? "")}`;
        const group = params.group !== undefined && params.group !== "" ? `&group=${encodeURIComponent(params.group)}` : "";
        return `${base}${group}&version=${encodeURIComponent(version)}`;
    };

    const allVersionsHref = () => {
        const base = `/components/overview?name=${encodeURIComponent(params.name ?? "")}`;
        const group = params.group !== undefined && params.group !== "" ? `&group=${encodeURIComponent(params.group)}` : "";
        return `${base}${group}`;
    };

    // Render an artifact row for a single entry (no arch).
    const ArtifactRow = (entry: ComponentVersionEntry) => (
        <tr>
            <td>
                <Show
                    when={entry.artifactId}
                    fallback={
                        <A href={`/sboms/${entry.sbomId}`}>
                            {entry.subjectVersion ?? formatDateTime(entry.sbomCreatedAt)}
                        </A>
                    }
                    keyed
                >
                    {(artifactId) => (
                        <>
                            <A href={`/artifacts/${artifactId}`}>
                                {entry.artifactName ?? artifactId.slice(0, 8)}
                            </A>
                            <Show when={entry.subjectVersion}>
                                <span class="text-muted">:{entry.subjectVersion}</span>
                            </Show>
                        </>
                    )}
                </Show>
            </td>
            <td>
                <Show
                    when={entry.sbomDigest}
                    fallback={<span class="text-muted">—</span>}
                    keyed
                >
                    {(digest) => (
                        <CopyDigest
                            digest={digest}
                            artifactName={entry.artifactName ?? undefined}
                        />
                    )}
                </Show>
            </td>
            <td
                class="whitespace-nowrap text-muted"
                title={new Date(entry.sbomCreatedAt).toLocaleString()}
            >
                {relativeDate(entry.sbomCreatedAt)}
            </td>
        </tr>
    );

    // Render arch-grouped artifact rows for a version group.
    const ArchArtifactTable = (entries: ComponentVersionEntry[]) => {
        const order: string[] = [];
        const map = new Map<string, ComponentVersionEntry[]>();
        for (const e of entries) {
            const key = e.subjectVersion ?? e.sbomId;
            if (!map.has(key)) {
                order.push(key);
                map.set(key, []);
            }
            map.get(key)?.push(e);
        }
        return (
            <table>
                <thead>
                    <tr>
                        <th>Artifact</th>
                        <th>Architectures</th>
                        <th>Ingested</th>
                    </tr>
                </thead>
                <tbody>
                    <For each={order}>
                        {(key) => {
                            const archEntries = map.get(key) ?? [];
                            const preferred =
                                archEntries.find((e) => e.architecture === "amd64") ??
                                archEntries[0];
                            return (
                                <>
                                    <tr style={{ "font-weight": "600" }}>
                                        <td>
                                            <Show
                                                when={preferred.artifactId}
                                                fallback={
                                                    <A href={`/sboms/${preferred.sbomId}`}>
                                                        {preferred.subjectVersion ??
                                                            formatDateTime(preferred.sbomCreatedAt)}
                                                    </A>
                                                }
                                                keyed
                                            >
                                                {(artifactId) => (
                                                    <>
                                                        <A href={`/artifacts/${artifactId}`}>
                                                            {preferred.artifactName ??
                                                                artifactId.slice(0, 8)}
                                                        </A>
                                                        <Show when={preferred.subjectVersion}>
                                                            <span class="text-muted">
                                                                :{preferred.subjectVersion}
                                                            </span>
                                                        </Show>
                                                    </>
                                                )}
                                            </Show>
                                        </td>
                                        <td>
                                            <For each={archEntries}>
                                                {(e) => (
                                                    <span
                                                        class="badge badge-primary"
                                                        style={{ "margin-right": "4px" }}
                                                    >
                                                        {e.architecture}
                                                    </span>
                                                )}
                                            </For>
                                        </td>
                                        <td
                                            class="whitespace-nowrap text-muted"
                                            title={new Date(
                                                preferred.sbomCreatedAt,
                                            ).toLocaleString()}
                                        >
                                            {relativeDate(preferred.sbomCreatedAt)}
                                        </td>
                                    </tr>
                                    <For each={archEntries}>
                                        {(e) => (
                                            <tr
                                                style={{
                                                    background: "var(--color-surface-hover)",
                                                }}
                                            >
                                                <td
                                                    style={{ "padding-left": "2rem" }}
                                                    colspan={3}
                                                >
                                                    <span
                                                        class="badge badge-primary"
                                                        style={{ "margin-right": "8px" }}
                                                    >
                                                        {e.architecture}
                                                    </span>
                                                    <A
                                                        href={`/sboms/${e.sbomId}`}
                                                        style={{ "margin-right": "12px" }}
                                                    >
                                                        SBOM
                                                    </A>
                                                    <Show when={e.sbomDigest} keyed>
                                                        {(digest) => (
                                                            <CopyDigest
                                                                digest={digest}
                                                                artifactName={
                                                                    e.artifactName ?? undefined
                                                                }
                                                            />
                                                        )}
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
        );
    };

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
                <Show when={!query.isLoading} fallback={<Loading />}>
                    <Show
                        when={!query.isError}
                        fallback={<ErrorBox error={query.error} />}
                    >
                        <Show
                            when={
                                query.data !== undefined &&
                                query.data.versions.length > 0
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
                                                    <Show
                                                        when={hasVersion()}
                                                        fallback={displayName()}
                                                    >
                                                        {displayName()}{" "}
                                                        <span class="font-mono">
                                                            {params.version}
                                                        </span>
                                                    </Show>
                                                </h2>
                                                <p class="text-muted">
                                                    <span class="badge">
                                                        {componentType()}
                                                    </span>{" "}
                                                    <Show
                                                        when={hasVersion()}
                                                        fallback={
                                                            <>
                                                                {plural(
                                                                    grouped().length,
                                                                    "version",
                                                                )}{" "}
                                                                across{" "}
                                                                {plural(
                                                                    qd.versions.length,
                                                                    "SBOM",
                                                                )}
                                                            </>
                                                        }
                                                    >
                                                        {plural(qd.versions.length, "artifact")}
                                                    </Show>
                                                </p>
                                            </div>
                                            <div class="btn-group">
                                                <Show when={hasVersion()}>
                                                    <A
                                                        href={allVersionsHref()}
                                                        class="btn btn-sm btn-secondary"
                                                    >
                                                        ← All versions
                                                    </A>
                                                </Show>
                                                <Show
                                                    when={
                                                        firstPurl() !== undefined
                                                            ? (purlToRegistryUrl(
                                                                  firstPurl() ?? "",
                                                              ) ?? undefined)
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
                                                            View on{" "}
                                                            {purlTypeLabel(
                                                                firstPurl() ?? "",
                                                            ) ?? "Registry"}
                                                        </a>
                                                    )}
                                                </Show>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Drill-down: artifact table for a specific version */}
                                    <Show when={hasVersion()}>
                                        <div class="card">
                                            <div class="table-wrapper">
                                                <Show
                                                    when={
                                                        qd.versions.some(
                                                            (e) => e.architecture !== undefined,
                                                        )
                                                    }
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
                                                                <For each={qd.versions}>
                                                                    {(entry) => ArtifactRow(entry)}
                                                                </For>
                                                            </tbody>
                                                        </table>
                                                    }
                                                >
                                                    {ArchArtifactTable(qd.versions)}
                                                </Show>
                                            </div>
                                        </div>
                                    </Show>

                                    {/* Summary: compact version list */}
                                    <Show when={!hasVersion()}>
                                        <div class="card">
                                            <div class="table-wrapper">
                                                <table>
                                                    <thead>
                                                        <tr>
                                                            <th>Version</th>
                                                            <th>Artifacts</th>
                                                            <th>Vulnerabilities</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <For each={grouped()}>
                                                            {(group) => {
                                                                const rep = group.entries[0];
                                                                return (
                                                                    <tr>
                                                                        <td>
                                                                            <A
                                                                                href={versionHref(
                                                                                    group.version,
                                                                                )}
                                                                                class="font-mono"
                                                                            >
                                                                                {group.version}
                                                                            </A>
                                                                            <Show
                                                                                when={group.purl}
                                                                                keyed
                                                                            >
                                                                                {(purl) => (
                                                                                    <span
                                                                                        style={{
                                                                                            "margin-left":
                                                                                                "8px",
                                                                                        }}
                                                                                    >
                                                                                        <PurlLink
                                                                                            purl={
                                                                                                purl
                                                                                            }
                                                                                            showBadge
                                                                                        />
                                                                                    </span>
                                                                                )}
                                                                            </Show>
                                                                        </td>
                                                                        <td class="text-muted">
                                                                            {plural(
                                                                                group.entries
                                                                                    .length,
                                                                                "artifact",
                                                                            )}
                                                                        </td>
                                                                        <td>
                                                                            <VulnCountBadges
                                                                                criticalCount={
                                                                                    rep.criticalCount
                                                                                }
                                                                                highCount={
                                                                                    rep.highCount
                                                                                }
                                                                                mediumCount={
                                                                                    rep.mediumCount
                                                                                }
                                                                                lowCount={
                                                                                    rep.lowCount
                                                                                }
                                                                                unknownCount={
                                                                                    rep.unknownCount
                                                                                }
                                                                            />
                                                                        </td>
                                                                    </tr>
                                                                );
                                                            }}
                                                        </For>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
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
