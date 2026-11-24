import { A } from "@solidjs/router";
import { Show, type JSX } from "solid-js";
import { useMyActivity, useMyClusters, useMyDriftFeed, useMySeenOnlyImages } from "~/api/queries";
import { relativeDate } from "~/utils/format";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Entries whose timestamp falls within the last `days` days of `now`. */
export function countSince<T>(rows: T[], at: (row: T) => string, days: number, now = Date.now()): number {
    return rows.filter((r) => now - new Date(at(r)).getTime() < days * DAY_MS).length;
}

/**
 * StatusFooter is the Workspace's health line: is anything still arriving,
 * did signing change, what runs without an SBOM, and is the cluster agent
 * still reporting. Each figure links to the page that owns it.
 */
export function StatusFooter(): JSX.Element {
    const activity = useMyActivity();
    const drift = useMyDriftFeed();
    const clusters = useMyClusters();
    const clusterIds = () => (clusters.data?.data ?? []).map((c) => c.id);
    const seenOnly = useMySeenOnlyImages(clusterIds);

    const latest = () => {
        let best: { id: string; name: string; at: string } | undefined;
        for (const c of clusters.data?.data ?? []) {
            if (c.lastSeenAt === undefined) continue;
            if (best === undefined || c.lastSeenAt > best.at) best = { id: c.id, name: c.name, at: c.lastSeenAt };
        }
        return best;
    };

    return (
        <footer class="ws-footer">
            <A href="/artifacts">
                <span class="ws-label">Ingested, 24 h</span>
                <br />
                <span class="ws-num">{countSince(activity.data?.data ?? [], (e) => e.createdAt, 1)}</span>{" "}
                <span class="ws-muted">SBOMs</span>
            </A>
            <A href="/admin/status">
                <span class="ws-label">Signing changes, 7 d</span>
                <br />
                <span class="ws-num">{countSince(drift.data?.data ?? [], (d) => d.detectedAt, 7)}</span>
            </A>
            <Show when={clusterIds().length > 0}>
                <A href={`/clusters/${clusterIds()[0]}?tab=gaps`}>
                    <span class="ws-label">Running, no SBOM</span>
                    <br />
                    <span class="ws-num">{seenOnly.data?.length ?? "—"}</span>{" "}
                    <span class="ws-muted">images</span>
                </A>
            </Show>
            <Show when={latest()}>
                {(c) => (
                    <A href={`/clusters/${c().id}`}>
                        <span class="ws-label">Cluster last reported</span>
                        <br />
                        <span class="ws-num">{relativeDate(c().at)}</span>{" "}
                        <span class="ws-muted">· {c().name}</span>
                    </A>
                )}
            </Show>
        </footer>
    );
}
