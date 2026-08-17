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
                    <For each={rows}>
                        {(a) => (
                            <PanelRow
                                href={`/sboms/${a.sbomId}`}
                                title={a.artifactName ?? a.namespaceName}
                                sub={[a.namespaceName, a.sourceName, a.subjectVersion]
                                    .filter((s) => s !== undefined && s !== "")
                                    .join(" · ")}
                                meta={relativeDate(a.createdAt)}
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
