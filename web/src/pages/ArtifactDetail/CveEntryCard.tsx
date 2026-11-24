import { A } from "@solidjs/router";
import { createSignal, For, Show, type JSX } from "solid-js";
import type { ComponentDiff } from "~/api/client";
import { DiffPairView } from "~/components/DiffPairView";
import { Card } from "~/components/ui";
import type { ChangelogEntryData, ChangelogVulnTotals } from "~/utils/diff";
import { changelogRefLabel } from "~/utils/diff";
import { buildTime, formatDate, plural } from "~/utils/format";

type Tally = ChangelogVulnTotals["closed"];
type ChangeVuln = NonNullable<ComponentDiff["closes"]>[number];

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

/** Rows shown before "N more". */
const ROWS_SHOWN = 7;

function tallyOf(vulns: readonly ChangeVuln[] | null | undefined): Tally {
    const t: Tally = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const v of vulns ?? []) {
        const k = v.severity.toLowerCase() as keyof Tally;
        if (k in t) t[k]++;
        else t.unknown++;
    }
    return t;
}

export function tallyTotal(t: Tally | undefined): number {
    return t === undefined ? 0 : t.critical + t.high + t.medium + t.low + t.unknown;
}

/** Changes that close or open a CVE, most criticals closed first. */
export function cveRows(changes: readonly ComponentDiff[]): ComponentDiff[] {
    return changes
        .filter((c) => (c.closes ?? []).length + (c.opens ?? []).length > 0)
        .sort((a, b) => {
            const ta = tallyOf(a.closes);
            const tb = tallyOf(b.closes);
            for (const s of SEVERITIES) if (ta[s] !== tb[s]) return tb[s] - ta[s];
            return a.name.localeCompare(b.name);
        });
}

/** An entry is flagged when it opened more CVEs than it closed. */
export function openedMoreThanClosed(v: ChangelogVulnTotals | undefined): boolean {
    return v !== undefined && tallyTotal(v.opened) > tallyTotal(v.closed);
}

/** Per-severity closed chips: a hatched swatch and a count, zeros omitted. */
function ClosedChips(props: { tally: Tally }): JSX.Element {
    return (
        <span class="cve-chips">
            <For each={SEVERITIES.filter((s) => props.tally[s] > 0)}>
                {(s) => (
                    <span title={`${props.tally[s]} ${s} closed`}>
                        <span class={`cve-sw cve-sw-${s}`} /> {props.tally[s]}
                    </span>
                )}
            </For>
        </span>
    );
}

/** "3 high, 1 medium" in the opened colour, or "opened none". */
function OpenedText(props: { tally: Tally; prefix?: string }): JSX.Element {
    const parts = () => SEVERITIES.filter((s) => props.tally[s] > 0).map((s) => `${props.tally[s]} ${s}`);
    return (
        <Show when={parts().length > 0} fallback={<span class="cve-none">opened none</span>}>
            <span class="cve-opened">
                <span class="cve-sw cve-sw-opened" /> {props.prefix ?? ""}
                {parts().join(", ")}
            </span>
        </Show>
    );
}

function idsLine(vulns: readonly ChangeVuln[] | null | undefined): string {
    const list = vulns ?? [];
    const shown = list.slice(0, 2).map((v) => v.id);
    return shown.join(" · ") + (list.length > 2 ? ` · +${list.length - 2}` : "");
}

function setKey(vulns: readonly ChangeVuln[] | null | undefined): string {
    return (vulns ?? [])
        .map((v) => v.id)
        .sort()
        .join(",");
}

/** "1.2 → 1.3", "added 1.3" or "removed 1.2". */
export function versionChange(c: ComponentDiff): string {
    if (c.type === "added") return `added ${c.version ?? ""}`.trim();
    if (c.type === "removed") return `removed ${c.version ?? ""}`.trim();
    return `${c.previousVersion ?? "—"} → ${c.version ?? "—"}`;
}

function CveRow(props: { change: ComponentDiff; sameAs?: string }): JSX.Element {
    const c = () => props.change;
    const closes = () => c().closes ?? [];
    const opens = () => c().opens ?? [];
    return (
        <div class="cve-row">
            <span class="cve-mono cve-ellipsis" title={c().name}>
                {c().name}
            </span>
            <span class="cve-mono cve-muted cve-ellipsis">{versionChange(c())}</span>
            <span>
                <Show when={props.sameAs === undefined} fallback={<span class="cve-muted">same {closes().length} CVEs as {props.sameAs}</span>}>
                    <Show when={closes().length > 0}>
                        <ClosedChips tally={tallyOf(closes())} />
                    </Show>
                    <Show when={opens().length > 0}>
                        <OpenedText tally={tallyOf(opens())} prefix="opened " />
                    </Show>
                </Show>
            </span>
            <span class="cve-mono cve-muted cve-small cve-ellipsis">
                <Show when={props.sameAs === undefined}>{idsLine(closes().length > 0 ? closes() : opens())}</Show>
            </span>
        </div>
    );
}

/**
 * CveEntryCard is one changelog entry read for its CVEs: what the release
 * closed and opened, and, expanded, the package changes behind it. With the
 * filter off the body is the full package diff, as before.
 */
export function CveEntryCard(props: {
    entry: ChangelogEntryData;
    cveOnly: boolean;
    viewMode: "tree" | "list";
}): JSX.Element {
    const [expanded, setExpanded] = createSignal(false);
    const [all, setAll] = createSignal(false);
    const e = () => props.entry;
    const rows = () => cveRows(e().changes);
    const flagged = () => openedMoreThanClosed(e().vulns);
    const quiet = () => tallyTotal(e().vulns?.closed) + tallyTotal(e().vulns?.opened) === 0;
    const shown = () => (all() ? rows() : rows().slice(0, ROWS_SHOWN));
    // A package whose closes repeat an earlier row's (libssl3 after
    // libcrypto3, one source package) says so instead of repeating them.
    const sameAs = (i: number): string | undefined => {
        const key = setKey(shown()[i].closes);
        if (key === "") return undefined;
        for (let j = 0; j < i; j++) if (setKey(shown()[j].closes) === key) return shown()[j].name;
        return undefined;
    };

    return (
        <Card class={`cve-entry${flagged() ? " cve-entry-flagged" : ""}${quiet() ? " cve-entry-quiet" : ""}`}>
            <div class="cve-head">
                <span class="cve-head-title">
                    <span class="cve-mono">
                        {/* Architecture and flavor are the timeline's, chosen above. */}
                        <A href={`/sboms/${e().from.id}`}>{e().from.subjectVersion ?? changelogRefLabel(e().from)}</A>
                        {" → "}
                        <A href={`/sboms/${e().to.id}`}>{e().to.subjectVersion ?? changelogRefLabel(e().to)}</A>
                    </span>
                    <span class="cve-muted cve-small">
                        {formatDate(buildTime(e().to))} ·{" "}
                        {e().changes.length === 0 ? "no package changes" : plural(e().changes.length, "change")}
                        <Show when={rows().length > 0}>, {rows().length} touch a CVE</Show>
                    </span>
                </span>
                <Show
                    when={!quiet()}
                    fallback={<span class="cve-muted cve-small">no CVE closed or opened</span>}
                >
                    <ClosedChips tally={e().vulns?.closed ?? tallyOf([])} />
                    <OpenedText tally={e().vulns?.opened ?? tallyOf([])} />
                </Show>
                <span class="cve-head-end">
                    <Show when={flagged()}>
                        <span class="cve-flag">opened more than it closed</span>
                    </Show>
                    <Show when={expanded()}>
                        <A href={`/diff?from=${e().from.id}&to=${e().to.id}`} class="cve-small">
                            Open as diff
                        </A>
                    </Show>
                    <button
                        type="button"
                        class="cve-toggle"
                        aria-expanded={expanded()}
                        onClick={() => setExpanded(!expanded())}
                    >
                        {expanded()
                            ? "Hide"
                            : props.cveOnly
                              ? rows().length > 0
                                  ? `Show ${plural(rows().length, "row")}`
                                  : "Show"
                              : "Show changes"}
                    </button>
                </span>
            </div>
            <Show when={expanded()}>
                <div class="cve-body">
                    <Show
                        when={props.cveOnly}
                        fallback={
                            <DiffPairView
                                fromId={e().from.id}
                                toId={e().to.id}
                                viewMode={props.viewMode}
                                hideHeader={true}
                            />
                        }
                    >
                        <For each={shown()}>{(c, i) => <CveRow change={c} sameAs={sameAs(i())} />}</For>
                        <p class="cve-foot cve-muted">
                            <Show when={!all() && rows().length > ROWS_SHOWN}>
                                <button type="button" class="link-button" onClick={() => setAll(true)}>
                                    {rows().length - ROWS_SHOWN} more rows
                                </button>{" "}
                                touch a CVE.{" "}
                            </Show>
                            {plural(e().changes.length - rows().length, "change")} touch no CVE: turn off the filter
                            to see them.
                        </p>
                    </Show>
                </div>
            </Show>
        </Card>
    );
}
