import { Show, For, createMemo, createSignal } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useComponentVersions, useComponentVulns } from "~/api/queries";
import type { ComponentVersionEntry } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import CopyDigest from "~/components/CopyDigest";
import PurlLink from "~/components/PurlLink";
import { VulnCountBadges, severityVariant } from "~/components/VulnBadge";
import { StatusPill } from "~/components/ui/Badge";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { relativeDate, formatDateTime, plural, hasText } from "~/utils/format";

interface VersionGroup {
    version: string;
    purl?: string;
    entries: ComponentVersionEntry[];
}

interface ArtifactGroup {
    key: string;
    artifactId?: string;
    artifactName?: string;
    entries: ComponentVersionEntry[];
}

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

    // Vuln data for the drill-down: use the first entry's id (all entries for the same
    // purl share the same vulnerability profile).
    const firstVersionId = () => query.data?.versions[0]?.id ?? "";
    const firstVersionPurl = () =>
        query.data?.versions.find((v) => v.purl !== undefined && v.purl !== "")?.purl ?? "";

    const vulnsQuery = useComponentVulns(() => firstVersionId(), {
        enabled: () => hasVersion() && firstVersionId() !== "" && hasText(firstVersionPurl()),
    });

    const displayName = () => {
        if (params.name === undefined) return "Unknown";
        return params.group !== undefined && params.group !== ""
            ? `${params.group}/${params.name}`
            : params.name;
    };

    // Version summary grouping (used in the top-level compact table).
    const grouped = createMemo<VersionGroup[]>(() => {
        if (hasVersion()) return [];
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

    // Artifact grouping for the drill-down hierarchical table.
    const artifactGroups = createMemo<ArtifactGroup[]>(() => {
        if (!hasVersion()) return [];
        const versions = query.data?.versions;
        if (!versions || versions.length === 0) return [];

        const order: string[] = [];
        const map = new Map<string, ArtifactGroup>();
        for (const e of versions) {
            const key = e.artifactId ?? e.sbomId;
            if (!map.has(key)) {
                order.push(key);
                map.set(key, {
                    key,
                    artifactId: e.artifactId ?? undefined,
                    artifactName: e.artifactName ?? undefined,
                    entries: [],
                });
            }
            map.get(key)?.entries.push(e);
        }
        return order.flatMap((k) => {
            const v = map.get(k);
            return v !== undefined ? [v] : [];
        });
    });

    const [expandedArtifacts, setExpandedArtifacts] = createSignal<Set<string>>(new Set());
    const toggleArtifact = (key: string) => {
        setExpandedArtifacts((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    };

    const componentType = () => query.data?.versions[0]?.type ?? "library";

    const firstPurl = () => {
        const versions = query.data?.versions;
        if (!versions) return undefined;
        return versions.find((v) => v.purl !== undefined)?.purl;
    };

    const versionHref = (version: string) => {
        const base = `/components/overview?name=${encodeURIComponent(params.name ?? "")}`;
        const group =
            params.group !== undefined && params.group !== ""
                ? `&group=${encodeURIComponent(params.group)}`
                : "";
        return `${base}${group}&version=${encodeURIComponent(version)}`;
    };

    const allVersionsHref = () => {
        const base = `/components/overview?name=${encodeURIComponent(params.name ?? "")}`;
        const group =
            params.group !== undefined && params.group !== ""
                ? `&group=${encodeURIComponent(params.group)}`
                : "";
        return `${base}${group}`;
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
                                                        {plural(
                                                            artifactGroups().length,
                                                            "artifact",
                                                        )}
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

                                    {/* ── Drill-down: specific version selected ── */}
                                    <Show when={hasVersion()}>
                                        {/* Vulnerability table */}
                                        <Show when={hasText(firstVersionPurl())}>
                                            <div class="card">
                                                <div class="card-header">
                                                    <h3>Vulnerabilities</h3>
                                                    <Show
                                                        when={vulnsQuery.data}
                                                        keyed
                                                    >
                                                        {(d) => (
                                                            <span class="badge">
                                                                {d.data.length}
                                                            </span>
                                                        )}
                                                    </Show>
                                                </div>
                                                <Show
                                                    when={
                                                        vulnsQuery.data &&
                                                        vulnsQuery.data.data.length > 0
                                                    }
                                                    fallback={
                                                        <Show
                                                            when={!vulnsQuery.isLoading}
                                                            fallback={<Loading />}
                                                        >
                                                            <EmptyState
                                                                title="No known vulnerabilities"
                                                                message="No vulnerabilities are currently recorded for this package."
                                                            />
                                                        </Show>
                                                    }
                                                >
                                                    <div class="table-wrapper">
                                                        <table>
                                                            <thead>
                                                                <tr>
                                                                    <th>CVE ID</th>
                                                                    <th>Severity</th>
                                                                    <th>CVSS</th>
                                                                    <th>Summary</th>
                                                                    <th>Fixed In</th>
                                                                </tr>
                                                            </thead>
                                                            <tbody>
                                                                <For
                                                                    each={
                                                                        vulnsQuery.data
                                                                            ?.data ?? []
                                                                    }
                                                                >
                                                                    {(v) => (
                                                                        <tr>
                                                                            <td class="font-mono text-sm">
                                                                                <A
                                                                                    href={`/vulnerabilities/${v.id}`}
                                                                                >
                                                                                    {v.id}
                                                                                </A>
                                                                            </td>
                                                                            <td>
                                                                                <StatusPill
                                                                                    variant={severityVariant(
                                                                                        v.severity,
                                                                                    )}
                                                                                >
                                                                                    {v.severity}
                                                                                </StatusPill>
                                                                            </td>
                                                                            <td>
                                                                                {v.cvssScore?.toFixed(
                                                                                    1,
                                                                                ) ?? "—"}
                                                                            </td>
                                                                            <td class="text-muted">
                                                                                {v.summary ?? "—"}
                                                                            </td>
                                                                            <td class="font-mono text-sm">
                                                                                {v.fixedVersion ??
                                                                                    "—"}
                                                                            </td>
                                                                        </tr>
                                                                    )}
                                                                </For>
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                </Show>
                                            </div>
                                        </Show>

                                        {/* Hierarchical collapsible artifact table */}
                                        <div class="card">
                                            <div class="card-header">
                                                <h3>Artifacts</h3>
                                                <span class="badge">
                                                    {artifactGroups().length}
                                                </span>
                                            </div>
                                            <div class="table-wrapper">
                                                <table>
                                                    <thead>
                                                        <tr>
                                                            <th
                                                                style={{
                                                                    width: "24px",
                                                                }}
                                                            />
                                                            <th>Artifact</th>
                                                            <th>SBOMs</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <For each={artifactGroups()}>
                                                            {(ag) => (
                                                                <>
                                                                    <tr
                                                                        style={{
                                                                            cursor: "pointer",
                                                                        }}
                                                                        onClick={() =>
                                                                            toggleArtifact(
                                                                                ag.key,
                                                                            )
                                                                        }
                                                                    >
                                                                        <td
                                                                            class="text-muted"
                                                                            style={{
                                                                                "font-size":
                                                                                    "0.7em",
                                                                                "user-select":
                                                                                    "none",
                                                                            }}
                                                                        >
                                                                            {expandedArtifacts().has(
                                                                                ag.key,
                                                                            )
                                                                                ? "▼"
                                                                                : "▶"}
                                                                        </td>
                                                                        <td>
                                                                            <Show
                                                                                when={
                                                                                    ag.artifactId
                                                                                }
                                                                                fallback={
                                                                                    <span>
                                                                                        {ag.artifactName ??
                                                                                            ag.key.slice(
                                                                                                0,
                                                                                                8,
                                                                                            )}
                                                                                    </span>
                                                                                }
                                                                                keyed
                                                                            >
                                                                                {(
                                                                                    artifactId,
                                                                                ) => (
                                                                                    <A
                                                                                        href={`/artifacts/${artifactId}`}
                                                                                        onClick={(
                                                                                            e,
                                                                                        ) =>
                                                                                            e.stopPropagation()
                                                                                        }
                                                                                    >
                                                                                        {ag.artifactName ??
                                                                                            artifactId.slice(
                                                                                                0,
                                                                                                8,
                                                                                            )}
                                                                                    </A>
                                                                                )}
                                                                            </Show>
                                                                        </td>
                                                                        <td class="text-muted">
                                                                            {plural(
                                                                                ag.entries
                                                                                    .length,
                                                                                "SBOM",
                                                                            )}
                                                                        </td>
                                                                    </tr>
                                                                    <Show
                                                                        when={expandedArtifacts().has(
                                                                            ag.key,
                                                                        )}
                                                                    >
                                                                        <For
                                                                            each={
                                                                                ag.entries
                                                                            }
                                                                        >
                                                                            {(e) => (
                                                                                <tr
                                                                                    style={{
                                                                                        background:
                                                                                            "var(--color-surface-hover)",
                                                                                    }}
                                                                                >
                                                                                    <td />
                                                                                    <td
                                                                                        style={{
                                                                                            "padding-left":
                                                                                                "2rem",
                                                                                        }}
                                                                                    >
                                                                                        <A
                                                                                            href={`/sboms/${e.sbomId}`}
                                                                                        >
                                                                                            {e.subjectVersion ??
                                                                                                formatDateTime(
                                                                                                    e.sbomCreatedAt,
                                                                                                )}
                                                                                        </A>
                                                                                        <Show
                                                                                            when={
                                                                                                e.architecture
                                                                                            }
                                                                                            keyed
                                                                                        >
                                                                                            {(
                                                                                                arch,
                                                                                            ) => (
                                                                                                <span
                                                                                                    class="badge badge-primary"
                                                                                                    style={{
                                                                                                        "margin-left":
                                                                                                            "8px",
                                                                                                    }}
                                                                                                >
                                                                                                    {
                                                                                                        arch
                                                                                                    }
                                                                                                </span>
                                                                                            )}
                                                                                        </Show>
                                                                                        <Show
                                                                                            when={
                                                                                                e.sbomDigest
                                                                                            }
                                                                                            keyed
                                                                                        >
                                                                                            {(
                                                                                                digest,
                                                                                            ) => (
                                                                                                <span
                                                                                                    style={{
                                                                                                        "margin-left":
                                                                                                            "12px",
                                                                                                    }}
                                                                                                >
                                                                                                    <CopyDigest
                                                                                                        digest={
                                                                                                            digest
                                                                                                        }
                                                                                                        artifactName={
                                                                                                            e.artifactName ??
                                                                                                            undefined
                                                                                                        }
                                                                                                    />
                                                                                                </span>
                                                                                            )}
                                                                                        </Show>
                                                                                    </td>
                                                                                    <td
                                                                                        class="whitespace-nowrap text-muted"
                                                                                        title={new Date(
                                                                                            e.sbomCreatedAt,
                                                                                        ).toLocaleString()}
                                                                                    >
                                                                                        {relativeDate(
                                                                                            e.sbomCreatedAt,
                                                                                        )}
                                                                                    </td>
                                                                                </tr>
                                                                            )}
                                                                        </For>
                                                                    </Show>
                                                                </>
                                                            )}
                                                        </For>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </Show>

                                    {/* ── Summary: compact version list ── */}
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
                                                                const rep =
                                                                    group.entries[0];
                                                                return (
                                                                    <tr>
                                                                        <td>
                                                                            <A
                                                                                href={versionHref(
                                                                                    group.version,
                                                                                )}
                                                                                class="font-mono"
                                                                            >
                                                                                {
                                                                                    group.version
                                                                                }
                                                                            </A>
                                                                            <Show
                                                                                when={
                                                                                    group.purl
                                                                                }
                                                                                keyed
                                                                            >
                                                                                {(
                                                                                    purl,
                                                                                ) => (
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
                                                                                group
                                                                                    .entries
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
