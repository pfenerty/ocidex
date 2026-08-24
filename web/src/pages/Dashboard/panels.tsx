import { For, type JSX } from "solid-js";
import { Boxes, Activity, ShieldAlert, GitCompareArrows, Server, Star } from "lucide-solid";
import { Panel, PanelBody, PanelRow } from "./Panel";
import { SeverityPill } from "~/components/cells";
import { StalenessPill } from "~/pages/Clusters";
import { relativeDate } from "~/utils/format";
import type { Cluster } from "~/api/client";
import type { components } from "~/types/openapi";
import {
    useMyNamespaces,
    useMyActivity,
    useMyDriftFeed,
    useMyVulnerabilities,
    useMyClusters,
    useWatchFeed,
} from "~/api/queries";

type Namespace = components["schemas"]["NamespaceResponse"];
type ActivityEntry = components["schemas"]["ActivityEntry"];
type DriftEntry = components["schemas"]["RecentDriftEntry"];
type TopVulnEntry = components["schemas"]["TopVulnEntry"];
type WatchEvent = components["schemas"]["WatchEvent"];

const ICON = 15;

/**
 * alertState reads a panel's own query rather than a separate count endpoint:
 * an alarm that could disagree with the rows underneath it is worse than no
 * alarm. Anything still in flight is "pending" — see Panel's `alert` prop.
 */
function alertState(query: {
    isLoading: boolean;
    data: { data: unknown[] } | undefined;
}): "raised" | "clear" | "pending" {
    if (query.isLoading || query.data === undefined) return "pending";
    return query.data.data.length > 0 ? "raised" : "clear";
}

/** NamespacesPanel — what the caller owns, which is the root of everything else
 *  on this page: sources, artifacts and visibility all hang off a namespace
 *  (ADR-039), so an empty namespace list explains an empty dashboard. */
export function NamespacesPanel(): JSX.Element {
    const query = useMyNamespaces();
    return (
        <Panel
            title="My namespaces"
            icon={<Boxes size={ICON} />}
            href="/admin/namespaces"
            linkLabel="Manage"
            count={query.data?.data.length}
        >
            <PanelBody query={query} empty="You do not own any namespaces yet.">
                {(rows: Namespace[]) => (
                    <For each={rows}>
                        {(ns) => (
                            <PanelRow
                                href="/admin/namespaces"
                                title={ns.name}
                                sub={ns.visibility}
                                meta={relativeDate(ns.created_at)}
                            />
                        )}
                    </For>
                )}
            </PanelBody>
        </Panel>
    );
}

/** One artifact's most recent ingest, plus how many older ones it hid. */
export interface IngestRow {
    entry: ActivityEntry;
    repeats: number;
}

/**
 * dedupeByArtifact collapses the activity feed to one row per artifact.
 *
 * A repository that pushes on every commit fills the whole panel with itself —
 * observed live with all five visible slots taken by one repo, so the feed
 * carried one fact five times and said nothing about the rest of the estate.
 * The entries arrive newest-first, so the first occurrence of an artifact is
 * the one to keep; the rest are counted rather than dropped, because "pushed 6
 * times today" is itself the interesting part.
 */
export function dedupeByArtifact(rows: ActivityEntry[]): IngestRow[] {
    const out: IngestRow[] = [];
    const byKey = new Map<string, IngestRow>();
    for (const entry of rows) {
        // artifactId is absent for an SBOM with no artifact subject; the name
        // and finally the SBOM id keep those rows distinct rather than
        // collapsing every one of them into a single line.
        const key = entry.artifactId ?? entry.artifactName ?? `sbom:${entry.sbomId}`;
        const seen = byKey.get(key);
        if (seen === undefined) {
            const row: IngestRow = { entry, repeats: 1 };
            byKey.set(key, row);
            out.push(row);
        } else {
            seen.repeats += 1;
        }
    }
    return out;
}

/** IngestPanel — recent SBOM ingests into owned namespaces. "Ingest health" is
 *  read off the stream itself rather than a separate status figure: the
 *  question this answers is "is anything still arriving, and from where". */
export function IngestPanel(): JSX.Element {
    const query = useMyActivity();
    return (
        <Panel
            title="Ingest activity"
            icon={<Activity size={ICON} />}
            href="/artifacts"
            linkLabel="All artifacts"
        >
            <PanelBody query={query} empty="Nothing has been ingested into your namespaces yet.">
                {(rows: ActivityEntry[]) => (
                    <For each={dedupeByArtifact(rows)}>
                        {(row) => (
                            <PanelRow
                                href={`/sboms/${row.entry.sbomId}`}
                                title={row.entry.artifactName ?? row.entry.namespaceName}
                                sub={[
                                    row.entry.namespaceName,
                                    row.entry.sourceName,
                                    row.entry.subjectVersion,
                                    row.repeats > 1 ? `${row.repeats} ingests` : undefined,
                                ]
                                    .filter((s) => s !== undefined && s !== "")
                                    .join(" · ")}
                                meta={relativeDate(row.entry.createdAt)}
                            />
                        )}
                    </For>
                )}
            </PanelBody>
        </Panel>
    );
}

/** DriftPanel — provenance drift on owned artifacts. Owned, not visible: the
 *  heading claims these are the caller's to fix (ocidex-998g.5). */
export function DriftPanel(): JSX.Element {
    const query = useMyDriftFeed();
    return (
        <Panel
            title="Provenance drift"
            icon={<GitCompareArrows size={ICON} />}
            href="/admin/status"
            linkLabel="System status"
            count={query.data?.data.length}
            alert={alertState(query)}
        >
            <PanelBody query={query} empty="No provenance drift on your artifacts.">
                {(rows: DriftEntry[]) => (
                    <For each={rows}>
                        {(d) => (
                            <PanelRow
                                href={`/sboms/${d.sbomId}`}
                                title={d.artifactName ?? d.sbomId}
                                sub={`${d.previousStatus} → ${d.newStatus} (${d.reason})`}
                                meta={relativeDate(d.detectedAt)}
                            />
                        )}
                    </For>
                )}
            </PanelBody>
        </Panel>
    );
}

/** ExposurePanel — vulnerabilities ranked by how much of what the caller owns
 *  they touch. */
export function ExposurePanel(): JSX.Element {
    const query = useMyVulnerabilities();
    return (
        <Panel
            title="Vulnerability exposure"
            icon={<ShieldAlert size={ICON} />}
            href="/vulnerabilities"
            count={query.data?.data.length}
            alert={alertState(query)}
        >
            <PanelBody query={query} empty="No known vulnerabilities in what you own.">
                {(rows: TopVulnEntry[]) => (
                    <For each={rows}>
                        {(v) => (
                            <PanelRow
                                href={`/vulnerabilities/${encodeURIComponent(v.canonicalId)}`}
                                title={v.canonicalId}
                                sub={
                                    <SeverityPill severity={v.severity}>{v.severity}</SeverityPill>
                                }
                                meta={`${v.affectedSbomCount} SBOMs`}
                            />
                        )}
                    </For>
                )}
            </PanelBody>
        </Panel>
    );
}

/** ClustersPanel — the caller's clusters and when each last reported (ADR-044).
 *  The meta slot carries the staleness pill rather than a bare timestamp: a
 *  cluster that stopped reporting still shows its last inventory everywhere
 *  else, so silence has to be stated where the cluster is listed (K5). */
export function ClustersPanel(): JSX.Element {
    const query = useMyClusters();
    return (
        <Panel
            title="My clusters"
            icon={<Server size={ICON} />}
            href="/clusters"
            linkLabel="Manage"
            count={query.data?.data.length}
        >
            <PanelBody
                query={query}
                empty="No clusters registered. Register one to see what your clusters actually run."
            >
                {(rows: Cluster[]) => (
                    <For each={rows}>
                        {(c) => (
                            <PanelRow
                                href={`/clusters/${c.id}`}
                                title={c.name}
                                sub={c.namespace_name}
                                meta={<StalenessPill lastSeenAt={c.last_seen_at} />}
                            />
                        )}
                    </For>
                )}
            </PanelBody>
        </Panel>
    );
}

/** watchEventHref sends each event kind to the page that actually explains it —
 *  a CVE to its own page, everything else to the SBOM it happened on. */
function watchEventHref(e: WatchEvent): string {
    if (e.kind === "vulnerability" && e.vulnerabilityId !== undefined) {
        return `/vulnerabilities/${encodeURIComponent(e.vulnerabilityId)}`;
    }
    return `/sboms/${e.sbomId}`;
}

/** watchEventSub states what changed, in the terms of the kind. Kept beside
 *  watchEventHref because both switch on the same discriminator and drifting
 *  apart would produce a line describing one thing and linking to another. */
function watchEventSub(e: WatchEvent): string {
    switch (e.kind) {
        case "new_version":
            return e.previousVersion !== undefined
                ? `new version ${e.version ?? "?"} (was ${e.previousVersion})`
                : `first version ${e.version ?? "?"}`;
        case "drift":
            return `provenance ${e.previousStatus ?? "?"} → ${e.newStatus ?? "?"}`;
        case "vulnerability":
            return `${e.severity ?? "unknown"} · ${e.vulnerabilityId ?? ""}`;
    }
}

/** WatchFeedPanel — the change feed for starred artifacts (ocidex-998g.4). It
 *  spans the full grid width because its rows carry the most text. */
export function WatchFeedPanel(): JSX.Element {
    const query = useWatchFeed();
    return (
        <Panel title="Watched artifacts" icon={<Star size={ICON} />} href="/artifacts">
            <PanelBody
                query={query}
                empty="Nothing new on the artifacts you watch. Star an artifact to follow it."
            >
                {(rows: WatchEvent[]) => (
                    <For each={rows}>
                        {(e) => (
                            <PanelRow
                                href={watchEventHref(e)}
                                title={e.artifactName}
                                sub={watchEventSub(e)}
                                meta={relativeDate(e.occurredAt)}
                            />
                        )}
                    </For>
                )}
            </PanelBody>
        </Panel>
    );
}
