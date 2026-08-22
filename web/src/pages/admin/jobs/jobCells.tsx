import { Show, type JSX } from "solid-js";
import { A } from "@solidjs/router";
import type { Column } from "~/components/DataTable";
import { TimestampCell } from "~/components/cells";

export const JOB_STATE_COLORS: Record<string, string> = {
    queued: "var(--color-text-muted)",
    running: "var(--color-info)",
    succeeded: "var(--color-success)",
    failed: "var(--color-danger)",
};

/**
 * JobRow is the slice of `ScanJob` and `EnrichmentJob` the shared columns read.
 * Both queues are the same outbox table shape (ADR-024), which is why the state
 * / worker / attempts / error / retry columns are literally the same cells —
 * they were duplicated verbatim between the two views before this file existed.
 */
export interface JobRow {
    id: string;
    state: string;
    worker_id?: string;
    attempts: number;
    created_at: string;
    last_error?: string;
    sbom_id?: string;
}

export function stateColumn<T extends JobRow>(): Column<T> {
    return {
        header: "State",
        render: (job) => (
            <span class="badge" style={{ color: JOB_STATE_COLORS[job.state] ?? "inherit" }}>
                {job.state}
            </span>
        ),
    };
}

export function workerColumn<T extends JobRow>(): Column<T> {
    return {
        header: "Worker",
        render: (job) => (
            <span style={{ "font-size": "0.8rem", color: "var(--color-text-muted)", "white-space": "nowrap" }}>
                {job.worker_id ?? "—"}
            </span>
        ),
    };
}

export function attemptsColumn<T extends JobRow>(): Column<T> {
    return { header: "Attempts", render: (job) => <>{job.attempts}</> };
}

export function createdColumn<T extends JobRow>(): Column<T> {
    return { header: "Created", render: (job) => <TimestampCell iso={job.created_at} /> };
}

/** DigestLine is the muted second line under an image name. */
export function DigestLine(props: { digest: string }): JSX.Element {
    return (
        <code style={{ display: "block", "font-size": "0.75rem", color: "var(--color-text-muted)", "margin-top": "0.15rem" }}>
            {props.digest.replace(/^sha256:/, "").slice(0, 12)}
        </code>
    );
}

/** lastErrorColumn expands in place; `expanded` is a `createExpandedSet()`. */
export function lastErrorColumn<T extends JobRow>(expanded: {
    has: (key: string) => boolean;
    toggle: (key: string) => void;
}): Column<T> {
    return {
        header: "Last Error",
        render: (job) => (
            <Show when={job.last_error}>
                <button
                    style={{ cursor: "pointer", "font-size": "0.85rem", background: "none", border: "none", padding: 0, color: "var(--color-secondary)" }}
                    onClick={() => expanded.toggle(job.id)}
                >
                    {expanded.has(job.id) ? "Hide error" : "View error"}
                </button>
                <Show when={expanded.has(job.id)}>
                    <code style={{ "font-size": "0.8rem", "word-break": "break-all", display: "block", "margin-top": "0.25rem" }}>
                        {job.last_error}
                    </code>
                </Show>
            </Show>
        ),
    };
}

export function sbomColumn<T extends JobRow>(): Column<T> {
    return {
        header: "SBOM",
        render: (job) => (
            <Show when={job.sbom_id}>
                <A href={`/sboms/${job.sbom_id}`} style={{ "font-size": "0.85rem" }}>
                    View SBOM
                </A>
            </Show>
        ),
    };
}

/** retryColumn is only offered for failed rows — the only retryable state. */
export function retryColumn<T extends JobRow>(retry: {
    isPending: boolean;
    mutate: (id: string) => void;
}): Column<T> {
    return {
        header: "Actions",
        render: (job) => (
            <Show when={job.state === "failed"}>
                <button
                    class="btn"
                    style={{ "font-size": "0.8rem", padding: "0.25rem 0.5rem" }}
                    disabled={retry.isPending}
                    onClick={() => retry.mutate(job.id)}
                >
                    Retry
                </button>
            </Show>
        ),
    };
}

/**
 * confirmRetryAll runs the "reset every failed row" mutation behind a confirm
 * and reports the count. Both queues expose the same bulk endpoint shape, and
 * the warning has to say "all failed rows, not just this page" in both.
 */
export async function confirmRetryAll(
    scopeLabel: string,
    noun: string,
    run: () => Promise<{ count: number }>,
): Promise<void> {
    if (!confirm(`Reset every 'failed' ${noun}_jobs row${scopeLabel} back to 'queued'? This affects all failed rows, not just the visible page.`)) {
        return;
    }
    try {
        const res = await run();
        alert(`Re-queued ${res.count} failed ${noun} job${res.count === 1 ? "" : "s"}.`);
    } catch (err) {
        alert(`Retry all failed: ${err instanceof Error ? err.message : String(err)}`);
    }
}
