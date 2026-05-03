import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactVersionSummary, PaginationMeta } from "~/api/client";
import Pagination from "~/components/Pagination";
import { relativeDate } from "~/utils/format";

export function VersionsTab(props: {
    versions: ArtifactVersionSummary[];
    pagination: PaginationMeta;
    onPageChange: (offset: number) => void;
}) {
    return (
        <div class="card">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Revision</th>
                            <th>Build Date</th>
                            <th>Architectures</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={props.versions}>
                            {(version) => (
                                <tr>
                                    <td>
                                        <A href={`/sboms/${version.sbomId}`}>
                                            {version.versionKey}
                                        </A>
                                    </td>
                                    <td>
                                        <Show
                                            when={version.revision}
                                            fallback={
                                                <span class="text-muted">—</span>
                                            }
                                        >
                                            {(rev) => (
                                                <Show
                                                    when={version.sourceUrl}
                                                    fallback={
                                                        <code title={rev()}>
                                                            {rev().slice(0, 7)}
                                                        </code>
                                                    }
                                                >
                                                    {(url) => (
                                                        <a
                                                            href={url()}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                        >
                                                            <code title={rev()}>
                                                                {rev().slice(0, 7)}
                                                            </code>
                                                        </a>
                                                    )}
                                                </Show>
                                            )}
                                        </Show>
                                    </td>
                                    <td
                                        class="nowrap text-muted"
                                        title={new Date(
                                            version.buildDate ?? version.createdAt,
                                        ).toLocaleString()}
                                    >
                                        {relativeDate(
                                            version.buildDate ?? version.createdAt,
                                        )}
                                    </td>
                                    <td>
                                        <Show
                                            when={
                                                version.architectures &&
                                                version.architectures.length > 0
                                            }
                                            fallback={
                                                <span class="text-muted">—</span>
                                            }
                                        >
                                            <For each={version.architectures ?? []}>
                                                {(arch) => (
                                                    <span
                                                        class="badge badge-primary"
                                                        style={{ "margin-right": "4px" }}
                                                    >
                                                        {arch}
                                                    </span>
                                                )}
                                            </For>
                                        </Show>
                                    </td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
            </div>
            <Pagination
                pagination={props.pagination}
                onPageChange={props.onPageChange}
            />
        </div>
    );
}
