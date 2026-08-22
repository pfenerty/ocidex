import { For, Show } from "solid-js";
import { A } from "@solidjs/router";
import CopyDigest from "~/components/CopyDigest";
import { Card, CardHeader, createExpandedSet } from "~/components/ui";
import { relativeDate, formatDateTime, plural } from "~/utils/format";
import type { ArtifactGroup } from "./grouping";

/**
 * ArtifactUsageTable lists the artifacts containing the selected version, each
 * expanding to the individual SBOMs it was seen in.
 */
export function ArtifactUsageTable(props: { groups: ArtifactGroup[] }) {
    const expanded = createExpandedSet();

    return (
        <Card>
            <CardHeader title="Artifacts" count={props.groups.length} />
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th style={{ width: "24px" }} />
                            <th>Artifact</th>
                            <th>SBOMs</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={props.groups}>
                            {(ag) => (
                                <>
                                    <tr class="cursor-pointer" onClick={() => expanded.toggle(ag.key)}>
                                        <td class="text-muted" style={{ "font-size": "0.7em", "user-select": "none" }}>
                                            {expanded.has(ag.key) ? "▼" : "▶"}
                                        </td>
                                        <td>
                                            <Show
                                                when={ag.artifactId}
                                                fallback={<span>{ag.artifactName ?? ag.key.slice(0, 8)}</span>}
                                                keyed
                                            >
                                                {(artifactId) => (
                                                    <A
                                                        href={`/artifacts/${artifactId}`}
                                                        onClick={(e) => e.stopPropagation()}
                                                    >
                                                        {ag.artifactName ?? artifactId.slice(0, 8)}
                                                    </A>
                                                )}
                                            </Show>
                                        </td>
                                        <td class="text-muted">{plural(ag.entries.length, "SBOM")}</td>
                                    </tr>
                                    <Show when={expanded.has(ag.key)}>
                                        <For each={ag.entries}>
                                            {(e) => (
                                                <tr style={{ background: "var(--color-surface-hover)" }}>
                                                    <td />
                                                    <td style={{ "padding-left": "2rem" }}>
                                                        <A href={`/sboms/${e.sbomId}`}>
                                                            {e.subjectVersion ?? formatDateTime(e.sbomCreatedAt)}
                                                        </A>
                                                        <Show when={e.architecture} keyed>
                                                            {(arch) => (
                                                                <span class="badge badge-primary ml-2">
                                                                    {arch}
                                                                </span>
                                                            )}
                                                        </Show>
                                                        <Show when={e.sbomDigest} keyed>
                                                            {(digest) => (
                                                                <span style={{ "margin-left": "12px" }}>
                                                                    <CopyDigest
                                                                        digest={digest}
                                                                        artifactName={e.artifactName ?? undefined}
                                                                    />
                                                                </span>
                                                            )}
                                                        </Show>
                                                    </td>
                                                    <td
                                                        class="whitespace-nowrap text-muted"
                                                        title={new Date(e.sbomCreatedAt).toLocaleString()}
                                                    >
                                                        {relativeDate(e.sbomCreatedAt)}
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
        </Card>
    );
}
