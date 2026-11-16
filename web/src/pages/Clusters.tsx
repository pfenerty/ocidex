import { Show } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Button, PageHeader, StatusChip, StatusPill } from "~/components/ui";
import "./ClusterDetail/ClusterDetail.css";
import { relativeDate } from "~/utils/format";
import type { Cluster } from "~/api/client";
import { useListClusters } from "~/api/queries";
import { AGENT_HEALTH_STATUS } from "~/utils/status";

type ClusterHealth = Cluster["health"];

/**
 * StalenessPill renders the agent's health, and it is deliberately the loudest
 * thing in the row.
 *
 * A cluster with no recent snapshot shows its *last* inventory, which looks
 * exactly like a current one. ADR-044 K5 is the rule this follows: an absence of
 * data must never read as an assertion of safety, so "never reported", "stale"
 * and "erroring" are stated as warnings rather than left to be inferred from a
 * timestamp the reader has to do arithmetic on.
 *
 * The server derives the state (ocidex-70eo.4): staleness against the agent's
 * own report interval, and erroring when it is pushing and being refused. The
 * reason is the pill's title. The client-side hour threshold below is only a
 * fallback for a response without health.
 */
const STALE_AFTER_MS = 60 * 60 * 1000;

export function StalenessPill(props: { lastSeenAt: string | undefined; health?: ClusterHealth }) {
    const seen = () => (props.lastSeenAt ?? "") !== "" ? props.lastSeenAt : undefined;
    const state = (): ClusterHealth["state"] => {
        if (props.health !== undefined) return props.health.state;
        const s = seen();
        if (s === undefined) return "never_reported";
        return Date.now() - new Date(s).getTime() > STALE_AFTER_MS ? "stale" : "healthy";
    };
    const reason = (fallback: string) => {
        const r = props.health?.reason;
        return r !== undefined && r !== "" ? r : fallback;
    };
    const when = () => {
        const s = seen();
        return s === undefined ? "" : ` · ${relativeDate(s)}`;
    };
    // Every state gets a chip, the healthy one included: a bare "9m ago" next
    // to four toned chips read as missing data (ocidex-iz0r.4).
    const status = () => AGENT_HEALTH_STATUS[state()];
    const suffix = () => (state() === "never_reported" || state() === "paused" ? "" : when());
    const title = () =>
        state() === "healthy" ? status().title : reason(status().title);
    return <StatusChip status={status()} suffix={suffix()} title={title()} />;
}

/** Problems first: the list exists to answer "is anything wrong?". */
const HEALTH_ORDER: Record<string, number> = {
    erroring: 0,
    stale: 1,
    never_reported: 2,
    healthy: 3,
    paused: 4,
};

/** One row's coverage as a compact bar, with its share matched in words. */
export function CoverageCell(props: { cluster: Cluster }) {
    return (
        <Show when={props.cluster.summary} fallback={<span class="text-muted">—</span>}>
            {(s) => {
                const c = () => s().coverage;
                const pct = (n: number) => (c().total === 0 ? 0 : (n / c().total) * 100);
                return (
                    <div class="grid gap-1">
                        <div class="coverage-bar compact" role="img" aria-label={`${Math.round(pct(c().matched))}% matched`}>
                            <Show when={c().matched > 0}>
                                <i class="coverage-bar-matched" style={{ width: `${pct(c().matched)}%` }} />
                            </Show>
                            <Show when={c().unknown > 0}>
                                <i class="coverage-bar-unknown" style={{ width: `${pct(c().unknown)}%` }} />
                            </Show>
                            <Show when={c().unresolvable > 0}>
                                <i class="coverage-bar-unresolvable" style={{ width: `${pct(c().unresolvable)}%` }} />
                            </Show>
                        </div>
                        <span class="text-muted text-sm">{Math.round(pct(c().matched))}% matched</span>
                    </div>
                );
            }}
        </Show>
    );
}

/**
 * Clusters answers "is any of my clusters in trouble?" without opening one
 * (ocidex-70eo.7): health with its reason, how much of what runs OCIDex can
 * assess, the criticals it found there, and the agent's version.
 *
 * Read-only on purpose. Editing, credentials, pausing and deleting live on the
 * cluster's Agent tab, beside the push history that explains the health.
 */
export default function Clusters() {
    const query = useListClusters();

    const rows = () =>
        [...(query.data?.data ?? [])].sort(
            (a, b) =>
                (HEALTH_ORDER[a.health.state] ?? 9) - (HEALTH_ORDER[b.health.state] ?? 9) ||
                a.name.localeCompare(b.name),
        );

    const columns: Column<Cluster>[] = [
        {
            header: "Cluster",
            sortKey: "name",
            sortValue: (c) => c.name,
            render: (c) => (
                <div class="grid">
                    <A href={`/clusters/${c.id}`}>{c.name}</A>
                    <span class="text-muted text-sm">{c.namespaceName ?? "—"}</span>
                </div>
            ),
        },
        {
            header: "Agent health",
            sortValue: (c) => HEALTH_ORDER[c.health.state] ?? 9,
            render: (c) => (
                <div class="grid justify-items-start gap-1">
                    <StalenessPill lastSeenAt={c.lastSeenAt} health={c.health} />
                    <Show when={c.health.state !== "healthy" && (c.health.reason ?? "") !== ""}>
                        <span class="text-muted text-sm cluster-health-reason clamp-2" title={c.health.reason}>
                            {c.health.reason}
                        </span>
                    </Show>
                    <Show when={c.health.state === "never_reported"}>
                        <A href={`/clusters/${c.id}`} class="text-sm">
                            finish connecting
                        </A>
                    </Show>
                </div>
            ),
        },
        {
            header: "Containers",
            align: "right",
            sortValue: (c) => c.summary?.coverage.total ?? -1,
            render: (c) => (
                <Show when={c.summary} fallback={<span class="text-muted">—</span>}>
                    {(s) => s().coverage.total.toLocaleString()}
                </Show>
            ),
        },
        {
            header: "Coverage",
            sortValue: (c) =>
                c.summary === undefined || c.summary.coverage.total === 0
                    ? -1
                    : c.summary.coverage.matched / c.summary.coverage.total,
            render: (c) => <CoverageCell cluster={c} />,
        },
        {
            header: "Running criticals",
            align: "right",
            sortValue: (c) => c.summary?.runningCriticals ?? -1,
            render: (c) => (
                <Show when={c.summary} fallback={<span class="text-muted">—</span>}>
                    {(s) => (
                        <span class={s().runningCriticals > 0 ? "sev-critical-text" : ""}>
                            {s().runningCriticals.toLocaleString()}
                        </span>
                    )}
                </Show>
            ),
        },
        {
            header: "Agent",
            render: (c) => (
                <Show when={c.agent} fallback={<span class="text-muted">—</span>}>
                    {(a) => (
                        <div class="grid">
                            <span>
                                {a().version ?? "unknown"}{" "}
                                <Show when={(a().versionSkew ?? "") !== ""}>
                                    <StatusPill variant="warning" title={a().versionSkew}>
                                        skew
                                    </StatusPill>
                                </Show>
                            </span>
                            <Show when={a().kubernetesVersion}>
                                {(v) => <span class="text-muted text-sm">k8s {v()}</span>}
                            </Show>
                        </div>
                    )}
                </Show>
            ),
        },
    ];

    return (
        <>
            <PageHeader
                title="Clusters"
                subtitle="What your Kubernetes clusters are running, and how much of it OCIDex can assess."
                actions={
                    <Button variant="primary" as={A} href="/clusters/new">
                        Connect a cluster
                    </Button>
                }
            />

            <DataTable
                columns={columns}
                rows={query.data ? rows() : undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No clusters connected"
                emptyMessage="Connect a cluster: name it, run one helm command against it, and its workloads appear here."
            />
        </>
    );
}
