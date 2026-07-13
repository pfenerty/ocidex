import "~/components/DetailSection.css";
import { Show } from "solid-js";
import type { GitCommitMetadata } from "~/api/client";
import { formatDateTime } from "~/utils/format";
import { GitCommitCell } from "~/components/cells";
import { GitHubIcon } from "./metadata/OciIcons";
import { LinkedField } from "./metadata/LinkedField";

export default function GitCommitCard(props: { commit: GitCommitMetadata }) {
    // eslint-disable-next-line solid/reactivity
    const c = props.commit;

    const repoUrl = () =>
        c.host !== undefined && c.owner !== undefined && c.repo !== undefined
            ? `https://${c.host}/${c.owner}/${c.repo}`
            : undefined;

    const committerDiffers = () =>
        c.committerName !== undefined && c.committerName !== c.authorName;

    return (
        <div class="card mb-4">
            <div class="card-header">
                <h3 style={{ display: "flex", "align-items": "center", gap: "0.5rem" }}>
                    <GitHubIcon />
                    Source Commit
                </h3>
            </div>

            <div class="detail-grid">
                {/* Repository */}
                <Show when={repoUrl()}>
                    {(url) => (
                        <LinkedField label="Repository" url={url()} display={`${c.owner}/${c.repo}`} />
                    )}
                </Show>

                {/* Commit */}
                <Show when={c.commitSha}>
                    {(sha) => (
                        <div class="detail-field">
                            <span class="detail-label">Commit</span>
                            <span class="detail-value">
                                <GitCommitCell sha={sha()} url={c.commitUrl} subject={c.messageSubject} />
                            </span>
                        </div>
                    )}
                </Show>

                {/* Message */}
                <Show when={c.messageSubject}>
                    <div class="detail-field">
                        <span class="detail-label">Message</span>
                        <span class="detail-value">{c.messageSubject}</span>
                    </div>
                </Show>

                {/* Author */}
                <Show when={c.authorName}>
                    <div class="detail-field">
                        <span class="detail-label">Author</span>
                        <span class="detail-value">
                            {c.authorName}
                            <Show when={c.authoredAt}>{(t) => <> · {formatDateTime(t())}</>}</Show>
                        </span>
                    </div>
                </Show>

                {/* Committer (only when distinct from author) */}
                <Show when={committerDiffers()}>
                    <div class="detail-field">
                        <span class="detail-label">Committer</span>
                        <span class="detail-value">
                            {c.committerName}
                            <Show when={c.committedAt}>{(t) => <> · {formatDateTime(t())}</>}</Show>
                        </span>
                    </div>
                </Show>

                {/* Parents */}
                <Show when={c.parents !== undefined && c.parents.length > 0 ? c.parents : undefined}>
                    {(parents) => (
                        <div class="detail-field">
                            <span class="detail-label">Parents</span>
                            <span class="detail-value font-mono text-sm">
                                {parents().map((p) => p.substring(0, 8)).join(", ")}
                            </span>
                        </div>
                    )}
                </Show>
            </div>
        </div>
    );
}
