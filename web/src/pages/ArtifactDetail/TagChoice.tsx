import { A } from "@solidjs/router";
import { Show, type JSX } from "solid-js";
import type { ArtifactVersionSummary } from "~/api/client";
import { useMyMoves } from "~/api/queries";
import { variantOf } from "~/utils/versionDelta";
import { plural } from "~/utils/format";
import "./TagChoice.css";

type Counts = NonNullable<ArtifactVersionSummary["vulns"]>;

/** "N critical · M findings with no fix", or that every finding has one. */
export function fixLine(v: Counts | undefined, matched: boolean): string {
    if (v === undefined) return matched ? "no known vulnerabilities" : "not scanned yet";
    const total = v.total;
    const unfixed = total - (v.fixable ?? 0);
    const crit = `${v.critical} critical`;
    if (unfixed <= 0) return `${crit} · all ${total} findings have an upstream fix`;
    return `${crit} · ${plural(unfixed, "finding")} with no fix`;
}

/**
 * The tag with the fewest criticals, then highs, among the newest scanned
 * version of each line (flavor and variant) on the page: the newest of every
 * line is a candidate, so a distroless build can beat its alpine sibling, but
 * an old tag that predates today's CVEs cannot win by being stale.
 * `versions` is newest first.
 */
export function fewestCriticals(versions: readonly ArtifactVersionSummary[]): ArtifactVersionSummary | undefined {
    const newestPerLine = new Map<string, ArtifactVersionSummary>();
    for (const v of versions) {
        if (!v.vulnMatched) continue;
        const line = `${v.flavor ?? ""}\u0000${variantOf(v.versionKey)}`;
        if (!newestPerLine.has(line)) newestPerLine.set(line, v);
    }
    let best: ArtifactVersionSummary | undefined;
    const key = (v: ArtifactVersionSummary) => [v.vulns?.critical ?? 0, v.vulns?.high ?? 0];
    for (const v of newestPerLine.values()) {
        if (best === undefined) {
            best = v;
            continue;
        }
        const [c, h] = key(v);
        const [bc, bh] = key(best);
        if (c < bc || (c === bc && h < bh)) best = v;
    }
    return best;
}

function Cell(props: { label: string; children: JSX.Element; lead?: boolean }): JSX.Element {
    return (
        <div class={props.lead === true ? "tag-cell tag-cell-lead" : "tag-cell"}>
            <span class="tag-cell-label">{props.label}</span>
            {props.children}
        </div>
    );
}

/** What the signed-in caller runs of this artifact, from their upgrade queue. */
function YouRun(props: { artifactId: string; signedIn: boolean }): JSX.Element {
    const moves = useMyMoves({ enabled: () => props.signedIn });
    const upgrade = () => moves.data?.upgrades.find((u) => u.artifactId === props.artifactId);
    return (
        <Show
            when={props.signedIn}
            fallback={
                <>
                    <span class="tag-cell-muted">Not known</span>
                    <span class="tag-cell-line">
                        <A href="/login">Sign in and connect a cluster</A> to see the move from yours
                    </span>
                </>
            }
        >
            <Show
                when={upgrade()}
                fallback={
                    <>
                        <span class="tag-cell-muted">No upgrade waiting</span>
                        <span class="tag-cell-line">
                            Either it is not running in your clusters or it is on its best tag.{" "}
                            <A href="/dashboard">Workspace</A>
                        </span>
                    </>
                }
            >
                {(u) => (
                    <>
                        <span class="tag-cell-tag">{u().running.tag}</span>
                        <span class="tag-cell-line">
                            move to <span class="tag-cell-mono">{u().target.tag}</span>: criticals{" "}
                            {u().before.critical} → {u().after.critical} ·{" "}
                            <A href={`/diff?from=${u().running.sbomId}&to=${u().target.sbomId}`}>diff</A>
                        </span>
                    </>
                )}
            </Show>
        </Show>
    );
}

/**
 * TagChoice answers "which tag should I run": the newest, the one with the
 * fewest criticals, and the one the caller runs. It reads the newest versions
 * page the band already loads, so it costs no request of its own except the
 * signed-in caller's upgrade queue.
 */
export function TagChoice(props: {
    artifactId: string;
    versions: readonly ArtifactVersionSummary[] | undefined;
    /** The headline version, as the band counts it. */
    newestKey: string | undefined;
    signedIn: boolean;
}): JSX.Element {
    const newest = () => {
        const list = props.versions ?? [];
        return list.find((v) => v.versionKey === props.newestKey) ?? list[0];
    };
    const best = () => fewestCriticals(props.versions ?? []);
    return (
        <Show when={newest()}>
            {(n) => (
                <section class="tag-choice" aria-label="Which tag to run">
                    <Cell label="Newest">
                        <span class="tag-cell-tag">{n().versionKey}</span>
                        <span class="tag-cell-line">{fixLine(n().vulns, n().vulnMatched)}</span>
                    </Cell>
                    <Cell label="Fewest criticals" lead>
                        <Show when={best()} fallback={<span class="tag-cell-muted">No scanned tag yet</span>}>
                            {(b) => (
                                <>
                                    <span class="tag-cell-tag">{b().versionKey}</span>
                                    <span class="tag-cell-line">{fixLine(b().vulns, b().vulnMatched)}</span>
                                </>
                            )}
                        </Show>
                    </Cell>
                    <Cell label="You run">
                        <YouRun artifactId={props.artifactId} signedIn={props.signedIn} />
                    </Cell>
                </section>
            )}
        </Show>
    );
}
