import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactRelation } from "~/api/client";
import { Card, TypeBadge } from "~/components/ui";
import { ErrorBox, EmptyState } from "~/components/Feedback";
import { SkeletonText } from "~/components/Skeleton";
import { relativeDate } from "~/utils/format";

// Three drift states, and they are deliberately not a boolean. The API returns
// isCurrent = undefined when it cannot tell (either side's version is unknown),
// which is a different thing from "up to date" and must not be reported as one.
type DriftState = "behind" | "current" | "unknown";

function driftOf(rel: ArtifactRelation): DriftState {
    if (rel.isCurrent === undefined) return "unknown";
    return rel.isCurrent ? "current" : "behind";
}

// Drift is the actionable part, so it sorts to the top; a run of up-to-date
// consumers is correct but boring and belongs at the bottom.
const driftRank: Record<DriftState, number> = {
    behind: 0,
    unknown: 1,
    current: 2,
};

function RelationCard(props: { relation: ArtifactRelation }) {
    const rel = () => props.relation;
    const drift = () => driftOf(rel());

    return (
        <Card
            class="mb-4"
            style={{
                padding: "0.75rem 1rem",
                display: "flex",
                "align-items": "center",
                "justify-content": "space-between",
                gap: "0.75rem",
                "flex-wrap": "wrap",
                // The left rule is the at-a-glance signal: a scan down the list
                // shows which consumers need attention without reading text.
                "border-left":
                    drift() === "behind"
                        ? "3px solid var(--color-warning)"
                        : "3px solid transparent",
            }}
        >
            <div
                style={{
                    display: "flex",
                    "align-items": "center",
                    gap: "0.5rem",
                    "min-width": "0",
                    "flex-wrap": "wrap",
                }}
            >
                <TypeBadge type={rel().artifactType} />
                <A href={`/artifacts/${rel().artifactId}`}>
                    {rel().artifactGroup !== undefined &&
                    rel().artifactGroup !== ""
                        ? `${rel().artifactGroup}/${rel().artifactName}`
                        : rel().artifactName}
                </A>
                <Show when={rel().subjectVersion}>
                    {(v) => <span class="font-mono text-sm">{v()}</span>}
                </Show>
                <Show when={rel().flavor}>
                    {(f) => <span class="badge">{f()}</span>}
                </Show>
                <Show when={rel().observedAt}>
                    {(at) => (
                        <span class="text-muted text-sm">
                            {relativeDate(at())}
                        </span>
                    )}
                </Show>
            </div>

            <div
                style={{
                    display: "flex",
                    "align-items": "center",
                    gap: "0.5rem",
                    "flex-wrap": "wrap",
                }}
            >
                <Show when={rel().matchedVersion}>
                    {(v) => (
                        <span class="text-sm">
                            ships{" "}
                            <A href={`/sboms/${rel().sbomId}`} class="font-mono">
                                {v()}
                            </A>
                        </span>
                    )}
                </Show>
                <Show when={drift() === "behind"}>
                    <span class="badge badge-warning">
                        Outdated
                        <Show when={rel().currentVersion}>
                            {(cur) => <> · current is {cur()}</>}
                        </Show>
                    </span>
                </Show>
                <Show when={drift() === "current"}>
                    <span class="text-muted text-sm">Up to date</span>
                </Show>
                <Show when={drift() === "unknown"}>
                    <span
                        class="text-muted text-sm"
                        title="One side has no comparable version, so drift cannot be determined."
                    >
                        Version unknown
                    </span>
                </Show>
            </div>
        </Card>
    );
}

export function RelationshipsTab(props: {
    artifactName: string;
    /** Artifacts whose latest SBOM ships this one (ADR-041 `usages`). */
    relations: ArtifactRelation[] | undefined;
    loading: boolean;
    isError: boolean;
    error?: unknown;
}) {
    const sorted = (): ArtifactRelation[] =>
        [...(props.relations ?? [])].sort(
            (a, b) =>
                driftRank[driftOf(a)] - driftRank[driftOf(b)] ||
                a.artifactName.localeCompare(b.artifactName),
        );

    const behindCount = () =>
        sorted().filter((r) => driftOf(r) === "behind").length;

    // Every entry carries the same currentVersion (it is a property of *this*
    // artifact, not of the consumer), so the first one is representative.
    const currentVersion = () => sorted()[0]?.currentVersion;

    return (
        <Show when={!props.loading} fallback={<SkeletonText lines={5} />}>
            <Show
                when={!props.isError}
                fallback={<ErrorBox error={props.error} />}
            >
                <Show
                    when={sorted().length > 0}
                    fallback={
                        <EmptyState
                            title="Not shipped anywhere yet"
                            message="No tracked artifact's latest SBOM contains this one. Ingest an SBOM for a consumer to see it here."
                        />
                    }
                >
                    <p class="text-muted mb-4">
                        <strong>{props.artifactName}</strong>
                        <Show when={currentVersion()}>
                            {(v) => <> {v()}</>}
                        </Show>
                        {" ships in "}
                        {sorted().length}
                        {sorted().length === 1 ? " artifact" : " artifacts"}
                        <Show when={behindCount() > 0}>
                            {" · "}
                            <span class="badge badge-warning">
                                {behindCount()} outdated
                            </span>
                        </Show>
                    </p>
                    <For each={sorted()}>
                        {(relation) => <RelationCard relation={relation} />}
                    </For>
                </Show>
            </Show>
        </Show>
    );
}
