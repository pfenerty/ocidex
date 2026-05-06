import { For, Show, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import { Loading, ErrorBox } from "~/components/Feedback";
import { formatDateTime } from "~/utils/format";
import { useListScanJobs } from "~/api/queries";

const JOB_STATE_COLORS: Record<string, string> = {
    queued: "var(--color-text-muted)",
    running: "var(--color-primary)",
    succeeded: "var(--color-success)",
    failed: "var(--color-error, #e53e3e)",
};

const PAGE_SIZE = 20;

export function JobsTab() {
    const [page, setPage] = createSignal(0);
    const [expandedErrors, setExpandedErrors] = createSignal(new Set<string>());
    const toggleError = (id: string) =>
        setExpandedErrors(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    const query = useListScanJobs(() => ({ limit: PAGE_SIZE, offset: page() * PAGE_SIZE }));

    const total = () => query.data?.pagination.total ?? 0;
    const pageCount = () => Math.max(1, Math.ceil(total() / PAGE_SIZE));

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div class="card">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>State</th>
                                    <th>Repository</th>
                                    <th>Attempts</th>
                                    <th>Created</th>
                                    <th>Last Error</th>
                                    <th>SBOM</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={query.data?.data ?? []}>
                                    {(job) => (
                                        <tr>
                                            <td>
                                                <span class="badge" style={{ color: JOB_STATE_COLORS[job.state] ?? "inherit" }}>
                                                    {job.state}
                                                </span>
                                            </td>
                                            <td>
                                                <code>{job.tag !== undefined ? `${job.repository}:${job.tag}` : job.repository}</code>
                                            </td>
                                            <td>{job.attempts}</td>
                                            <td style={{ "white-space": "nowrap" }}>{formatDateTime(job.created_at)}</td>
                                            <td>
                                                <Show when={job.last_error}>
                                                    <button
                                                        style={{ cursor: "pointer", "font-size": "0.85rem", background: "none", border: "none", padding: 0, color: "var(--color-primary)" }}
                                                        onClick={() => toggleError(job.id)}
                                                    >
                                                        {expandedErrors().has(job.id) ? "Hide error" : "View error"}
                                                    </button>
                                                    <Show when={expandedErrors().has(job.id)}>
                                                        <code style={{ "font-size": "0.8rem", "word-break": "break-all", display: "block", "margin-top": "0.25rem" }}>
                                                            {job.last_error}
                                                        </code>
                                                    </Show>
                                                </Show>
                                            </td>
                                            <td>
                                                <Show when={job.sbom_id}>
                                                    <A href={`/sboms/${job.sbom_id}`} style={{ "font-size": "0.85rem" }}>
                                                        View SBOM
                                                    </A>
                                                </Show>
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                    <Show when={pageCount() > 1}>
                        <div style={{ display: "flex", gap: "0.5rem", "align-items": "center", "margin-top": "1rem", "justify-content": "flex-end" }}>
                            <button class="btn" disabled={page() === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
                            <span style={{ "font-size": "0.85rem" }}>Page {page() + 1} of {pageCount()}</span>
                            <button class="btn" disabled={page() + 1 >= pageCount()} onClick={() => setPage(p => p + 1)}>Next</button>
                        </div>
                    </Show>
                </div>
            </Show>
        </Show>
    );
}
