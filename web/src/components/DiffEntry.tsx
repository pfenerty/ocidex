import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { relativeDate } from "~/utils/format";
import { classifyChange, changelogRefLabel } from "~/utils/diff";
import type { ChangelogEntryData } from "~/utils/diff";
import PurlLink from "~/components/PurlLink";
import { parsePurl } from "~/utils/purl";

interface DiffEntryProps {
    entry: ChangelogEntryData;
    packagesOnly: boolean;
    showPlanFiles: boolean;
    typeFilter: string | null;
    nameFilter: string;
    onTypeFilterToggle: (kind: string) => void;
}

export default function DiffEntry(props: DiffEntryProps) {
    // Applies only the packagesOnly filter — used as the "show this entry at all" baseline.
    const baseChanges = () =>
        props.packagesOnly
            ? props.entry.changes.filter((c) => c.purl !== undefined)
            : props.entry.changes;

    // Applies packagesOnly + showPlanFiles: removes entries with no purl or purl type "file".
    const pkgChanges = () => {
        if (!props.showPlanFiles) {
            return baseChanges().filter(
                (c) => c.purl !== undefined && parsePurl(c.purl)?.type !== "file",
            );
        }
        return baseChanges();
    };

    const visibleChanges = () => {
        const f = props.typeFilter;
        const q = props.nameFilter.toLowerCase().trim();
        let changes = f !== null ? pkgChanges().filter(c => classifyChange(c) === f) : pkgChanges();
        if (q) {
            changes = changes.filter(c =>
                c.name.toLowerCase().includes(q) ||
                (c.group?.toLowerCase().includes(q) ?? false) ||
                (c.purl?.toLowerCase().includes(q) ?? false)
            );
        }
        return changes;
    };

    const addedCount = () => pkgChanges().filter((c) => c.type === "added").length;
    const removedCount = () => pkgChanges().filter((c) => c.type === "removed").length;
    const upgradedCount = () => pkgChanges().filter((c) => classifyChange(c) === "upgraded").length;
    const downgradedCount = () => pkgChanges().filter((c) => classifyChange(c) === "downgraded").length;

    const hiddenByPlanFilter = () => !props.showPlanFiles && baseChanges().length > pkgChanges().length;

    return (
        <Show when={baseChanges().length > 0}>
            <div class="changelog-entry">
                <div class="changelog-entry-header">
                    <div class="text-sm">
                        <A href={`/sboms/${props.entry.from.id}`} class="mono">
                            {changelogRefLabel(props.entry.from)}
                        </A>
                        {" → "}
                        <A href={`/sboms/${props.entry.to.id}`} class="mono">
                            {changelogRefLabel(props.entry.to)}
                        </A>
                        <span class="text-muted">
                            {" "}
                            ({relativeDate(props.entry.to.buildDate ?? props.entry.to.createdAt)})
                        </span>
                    </div>
                    <div class="changelog-summary">
                        {(() => {
                            const kinds = [
                                { key: "added",      count: addedCount(),      cls: "badge-success", label: (n: number) => `+${n} added` },
                                { key: "removed",    count: removedCount(),    cls: "badge-danger",  label: (n: number) => `-${n} removed` },
                                { key: "upgraded",   count: upgradedCount(),   cls: "badge-success", label: (n: number) => `↑${n} upgraded` },
                                { key: "downgraded", count: downgradedCount(), cls: "badge-danger",  label: (n: number) => `↓${n} downgraded` },
                            ];
                            return kinds
                                .filter(k => k.count > 0)
                                .map(k => (
                                    <button
                                        class={`badge ${k.cls}`}
                                        style={{
                                            cursor: "pointer",
                                            border: "none",
                                            opacity: props.typeFilter !== null && props.typeFilter !== k.key ? "0.45" : "1",
                                            "font-weight": props.typeFilter === k.key ? "700" : undefined,
                                        }}
                                        onClick={() => props.onTypeFilterToggle(k.key)}
                                        title={props.typeFilter === k.key ? "Click to clear filter" : `Click to show only ${k.key}`}
                                    >
                                        {k.label(k.count)}
                                    </button>
                                ));
                        })()}
                        <Show when={hiddenByPlanFilter()}>
                            <span class="text-muted text-sm">
                                {baseChanges().length - pkgChanges().length} plan file {baseChanges().length - pkgChanges().length === 1 ? "change" : "changes"} hidden
                            </span>
                        </Show>
                    </div>
                </div>
                <Show when={visibleChanges().length > 0} fallback={
                    <p class="text-muted text-sm" style={{ padding: "0.5rem 0" }}>
                        No changes match the current filter.
                    </p>
                }>
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Change</th>
                                    <th>Component</th>
                                    <th>Version</th>
                                    <th>Package</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={visibleChanges()}>
                                    {(change) => (
                                        <tr>
                                            <td>
                                                {(() => {
                                                    const kind = classifyChange(change);
                                                    const cls =
                                                        kind === "added" || kind === "upgraded"
                                                            ? "badge-success"
                                                            : kind === "removed" || kind === "downgraded"
                                                              ? "badge-danger"
                                                              : "badge-warning";
                                                    return <span class={`badge ${cls}`}>{kind}</span>;
                                                })()}
                                            </td>
                                            <td>
                                                <A href={(() => {
                                                    const p = new URLSearchParams({ name: change.name });
                                                    if (change.group !== undefined) p.set("group", change.group);
                                                    return `/components/overview?${p.toString()}`;
                                                })()}>
                                                    <Show when={change.group}>
                                                        <span class="text-muted">{change.group}/</span>
                                                    </Show>
                                                    {change.name}
                                                </A>
                                            </td>
                                            <td class="mono">
                                                <Show when={change.previousVersion}>
                                                    <span class="text-muted">{change.previousVersion}</span>
                                                    {" → "}
                                                </Show>
                                                {change.version ?? "—"}
                                            </td>
                                            <td class="mono truncate text-muted">
                                                <Show when={change.purl} fallback={"—"}>
                                                    {(purl) => <PurlLink purl={purl()} />}
                                                </Show>
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                </Show>
            </div>
        </Show>
    );
}
