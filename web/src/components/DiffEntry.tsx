import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { relativeDate } from "~/utils/format";
import { changelogRefLabel } from "~/utils/diff";
import type { ChangelogEntryData } from "~/utils/diff";
import type { ComponentDiff } from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import PurlLink from "~/components/PurlLink";
import { parsePurl } from "~/utils/purl";

const changeColumns: Column<ComponentDiff>[] = [
    {
        header: "Change",
        render: (change) => (
            <span
                class={`badge ${
                    change.direction === "added" || change.direction === "upgraded"
                        ? "badge-primary"
                        : "badge-warning"
                }`}
            >
                {change.direction}
            </span>
        ),
    },
    {
        header: "Component",
        render: (change) => {
            const params = new URLSearchParams({ name: change.name });
            if (change.group !== undefined) params.set("group", change.group);
            return (
                <A href={`/components/overview?${params.toString()}`}>
                    <Show when={change.group}>
                        <span class="text-muted">{change.group}/</span>
                    </Show>
                    {change.name}
                </A>
            );
        },
    },
    {
        header: "Version",
        class: "font-mono text-sm",
        render: (change) => (
            <>
                <Show when={change.previousVersion}>
                    <span class="text-muted">{change.previousVersion}</span>
                    {" → "}
                </Show>
                {change.version ?? "—"}
            </>
        ),
    },
    {
        header: "Package",
        class: "mono truncate text-muted",
        render: (change) => (
            <Show when={change.purl} fallback={"—"}>
                {(purl) => <PurlLink purl={purl()} />}
            </Show>
        ),
    },
];

interface DiffEntryProps {
    entry: ChangelogEntryData;
    packagesOnly: boolean;
    typeFilter: string | null;
    nameFilter: string;
    onTypeFilterToggle: (kind: string) => void;
    hideHeader?: boolean;
}

export default function DiffEntry(props: DiffEntryProps) {
    // File-type entries (no purl, or purl type "file") are never shown.
    const pkgChanges = () => {
        const changes = props.packagesOnly
            ? props.entry.changes.filter((c) => c.purl !== undefined)
            : props.entry.changes;
        return changes.filter((c) => parsePurl(c.purl ?? "")?.type !== "file");
    };

    const visibleChanges = () => {
        const f = props.typeFilter;
        const q = props.nameFilter.toLowerCase().trim();
        let changes = f !== null ? pkgChanges().filter(c => c.direction === f) : pkgChanges();
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
    const upgradedCount = () => pkgChanges().filter((c) => c.direction === "upgraded").length;
    const downgradedCount = () => pkgChanges().filter((c) => c.direction === "downgraded").length;

    return (
        <Show when={visibleChanges().length > 0}>
            <div class="changelog-entry">
                <Show when={props.hideHeader !== true}>
                    <div class="changelog-entry-header">
                        <div class="text-sm">
                            <A href={`/sboms/${props.entry.from.id}`} class="font-mono">
                                {changelogRefLabel(props.entry.from)}
                            </A>
                            {" → "}
                            <A href={`/sboms/${props.entry.to.id}`} class="font-mono">
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
                                    { key: "added",      count: addedCount(),      cls: "badge-primary", label: (n: number) => `+${n} added` },
                                    { key: "removed",    count: removedCount(),    cls: "badge-warning", label: (n: number) => `-${n} removed` },
                                    { key: "upgraded",   count: upgradedCount(),   cls: "badge-primary", label: (n: number) => `↑${n} upgraded` },
                                    { key: "downgraded", count: downgradedCount(), cls: "badge-warning", label: (n: number) => `↓${n} downgraded` },
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
                        </div>
                    </div>
                </Show>
                <DataTable
                    bare
                    columns={changeColumns}
                    rows={visibleChanges()}
                    loading={false}
                    isError={false}
                    emptyTitle="No changes match this filter"
                />
            </div>
        </Show>
    );
}
