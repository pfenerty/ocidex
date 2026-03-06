import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { SBOMSummary, PaginationMeta } from "~/api/client";
import Pagination from "~/components/Pagination";
import CopyDigest from "~/components/CopyDigest";
import { sbomShortLabel, relativeDate, plural } from "~/utils/format";
import { groupSBOMsByVersionAndArch } from "~/utils/groupSBOMs";

export function SBOMsTab(props: {
    sboms: SBOMSummary[];
    pagination: PaginationMeta;
    artifactId: string;
    artifactName: string;
    artifactType: string;
    onPageChange: (offset: number) => void;
}) {
    const hasArch = () => props.sboms.some((s) => s.architecture !== undefined);

    // Group by version key; keep only newest SBOM per arch per version.
    // API returns rows ORDER BY created_at DESC so first-seen per (version, arch) is newest.
    const groups = () => {
        if (!hasArch()) return null;
        return groupSBOMsByVersionAndArch(props.sboms);
    };

    return (
        <div class="card">
            <div class="table-wrapper">
                <Show
                    when={hasArch()}
                    fallback={
                        <table>
                            <thead>
                                <tr>
                                    <th>Version</th>
                                    <th>Components</th>
                                    <th>Digest</th>
                                    <th>Build Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={props.sboms}>
                                    {(sbom) => (
                                        <tr>
                                            <td>
                                                <A href={`/sboms/${sbom.id}`}>
                                                    {sbomShortLabel(sbom)}
                                                </A>
                                            </td>
                                            <td>
                                                <Show
                                                    when={
                                                        sbom.componentCount !==
                                                        undefined
                                                    }
                                                    fallback={
                                                        <span class="text-muted">
                                                            —
                                                        </span>
                                                    }
                                                >
                                                    {plural(
                                                        sbom.componentCount ??
                                                            0,
                                                        "component",
                                                    )}
                                                </Show>
                                            </td>
                                            <td>
                                                <Show
                                                    when={sbom.digest}
                                                    fallback={
                                                        <span class="text-muted">
                                                            —
                                                        </span>
                                                    }
                                                >
                                                    {(digest) => (
                                                        <CopyDigest
                                                            digest={digest()}
                                                            artifactName={
                                                                props.artifactName
                                                            }
                                                        />
                                                    )}
                                                </Show>
                                            </td>
                                            <td
                                                class="nowrap text-muted"
                                                title={new Date(
                                                    sbom.buildDate ??
                                                        sbom.createdAt,
                                                ).toLocaleString()}
                                            >
                                                {relativeDate(
                                                    sbom.buildDate ??
                                                        sbom.createdAt,
                                                )}
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
                                <th>Version</th>
                                <th>Revision</th>
                                <th>Build Date</th>
                                <th>Architectures</th>
                                <th>Components</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={groups()?.versionOrder ?? []}>
                                {(vKey) => {
                                    const archMap =
                                        groups()?.versionMap.get(vKey) ??
                                        new Map<string, SBOMSummary>();
                                    const sboms = [...archMap.values()];
                                    const newest = sboms.reduce((a, b) =>
                                        new Date(a.buildDate ?? a.createdAt) >=
                                        new Date(b.buildDate ?? b.createdAt)
                                            ? a
                                            : b,
                                    );
                                    const total = sboms.reduce(
                                        (n, s) => n + (s.componentCount ?? 0),
                                        0,
                                    );
                                    const revision = newest.revision;
                                    return (
                                        <tr>
                                            <td>
                                                <A
                                                    href={`/artifacts/${props.artifactId}/versions/${encodeURIComponent(vKey)}`}
                                                >
                                                    {vKey}
                                                </A>
                                            </td>
                                            <td>
                                                <Show
                                                    when={revision}
                                                    fallback={<span class="text-muted">—</span>}
                                                >
                                                    {(rev) => (
                                                        <Show
                                                            when={newest.sourceUrl}
                                                            fallback={
                                                                <code title={rev()}>{rev().slice(0, 7)}</code>
                                                            }
                                                        >
                                                            {(url) => (
                                                                <a href={url()} target="_blank" rel="noopener noreferrer">
                                                                    <code title={rev()}>{rev().slice(0, 7)}</code>
                                                                </a>
                                                            )}
                                                        </Show>
                                                    )}
                                                </Show>
                                            </td>
                                            <td
                                                class="nowrap text-muted"
                                                title={new Date(
                                                    newest.buildDate ??
                                                        newest.createdAt,
                                                ).toLocaleString()}
                                            >
                                                {relativeDate(
                                                    newest.buildDate ??
                                                        newest.createdAt,
                                                )}
                                            </td>
                                            <td>
                                                <For each={sboms}>
                                                    {(s) => (
                                                        <A
                                                            href={`/sboms/${s.id}`}
                                                            style={{
                                                                "margin-right":
                                                                    "4px",
                                                            }}
                                                        >
                                                            <span class="badge badge-primary">
                                                                {s.architecture}
                                                            </span>
                                                        </A>
                                                    )}
                                                </For>
                                            </td>
                                            <td>
                                                <Show
                                                    when={total > 0}
                                                    fallback={
                                                        <span class="text-muted">
                                                            —
                                                        </span>
                                                    }
                                                >
                                                    {plural(total, "component")}
                                                </Show>
                                            </td>
                                        </tr>
                                    );
                                }}
                            </For>
                            <For
                                each={props.sboms.filter(
                                    (s) => s.architecture === undefined,
                                )}
                            >
                                {(sbom) => (
                                    <tr>
                                        <td>
                                            <A href={`/sboms/${sbom.id}`}>
                                                {sbomShortLabel(sbom)}
                                            </A>
                                        </td>
                                        <td><span class="text-muted">—</span></td>
                                        <td
                                            class="nowrap text-muted"
                                            title={new Date(
                                                sbom.buildDate ??
                                                    sbom.createdAt,
                                            ).toLocaleString()}
                                        >
                                            {relativeDate(
                                                sbom.buildDate ??
                                                    sbom.createdAt,
                                            )}
                                        </td>
                                        <td>—</td>
                                        <td>
                                            <Show
                                                when={
                                                    sbom.componentCount !==
                                                    undefined
                                                }
                                                fallback={
                                                    <span class="text-muted">
                                                        —
                                                    </span>
                                                }
                                            >
                                                {plural(
                                                    sbom.componentCount ?? 0,
                                                    "component",
                                                )}
                                            </Show>
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </Show>
            </div>
            <Pagination
                pagination={props.pagination}
                onPageChange={props.onPageChange}
            />
        </div>
    );
}
