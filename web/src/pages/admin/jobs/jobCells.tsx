import { Show, type JSX } from "solid-js";
import { A } from "@solidjs/router";
import type { Column } from "~/components/DataTable";
import { TimestampCell } from "~/components/cells";
import { Button } from "~/components/ui";

export const JOB_STATE_COLORS: Record<string, string> = {
    queued: "var(--color-text-muted)",
    running: "var(--color-info)",
    succeeded: "var(--color-success)",
    failed: "var(--color-danger)",
    // The SBOM was deleted on purpose; the walk will not scan it again (ADR-0053).
    pruned: "var(--color-text-muted)",
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
        // Only a running job holds a lease. A worker beside "queued" read as a
        // job one worker had claimed and never let go (ocidex-nps9.26).
        render: (job) => (
            <span class="text-[0.8rem] whitespace-nowrap text-[var(--color-text-muted)]">
                {job.state === "running" ? (job.worker_id ?? "—") : "—"}
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
        <code class="mt-[0.15rem] block text-[0.75rem] text-[var(--color-text-muted)]">
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
                    class="cursor-pointer border-none bg-transparent p-0 text-[0.85rem] text-[var(--color-secondary)]"
                    onClick={() => expanded.toggle(job.id)}
                >
                    {expanded.has(job.id) ? "Hide error" : "View error"}
                </button>
                <Show when={expanded.has(job.id)}>
                    <code class="mt-1 block text-[0.8rem] break-all">
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
                <A href={`/sboms/${job.sbom_id}`} class="text-sm">
                    View SBOM
                </A>
            </Show>
        ),
    };
}

/**
 * retryColumn offers Retry on failed rows, and Cancel on queued ones when the
 * queue supports it (scan jobs do).
 */
export function retryColumn<T extends JobRow>(
    retry: {
        isPending: boolean;
        mutate: (id: string) => void;
    },
    cancel?: {
        isPending: boolean;
        mutate: (id: string) => void;
    },
): Column<T> {
    return {
        header: "Actions",
        render: (job) => (
            <>
                <Show when={job.state === "failed"}>
                    <Button
                        size="sm"
                        disabled={retry.isPending}
                        onClick={() => retry.mutate(job.id)}
                    >
                        Retry
                    </Button>
                </Show>
                <Show when={cancel !== undefined && job.state === "queued" ? cancel : undefined}>
                    {(c) => (
                        <Button
                            size="sm"
                            disabled={c().isPending}
                            onClick={() => c().mutate(job.id)}
                        >
                            Cancel
                        </Button>
                    )}
                </Show>
            </>
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
