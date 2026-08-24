import { createEffect, createMemo, createSignal, Show, For } from "solid-js";
import { createLocalStorageSignal } from "~/utils/prefs";
import { A } from "@solidjs/router";
import { Button } from "~/components/ui";
import { relativeDate } from "~/utils/format";
import { changelogRefLabel } from "~/utils/diff";
import type { DiffTree } from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import {
    buildTreeModel,
    changeBadgeClass,
    flattenVisibleRows,
    type Row,
    type TreeModel,
} from "./diffTreeModel";

/**
 * The tree's rows and the orphan changes appended below them are different
 * shapes sharing three columns, so they meet as a discriminated union rather
 * than as two `<For>`s inside one hand-written `<tbody>`.
 *
 * An orphan is a change whose component is in no dependency edge (ADR-021):
 * it has no depth, no children and no descendant rollup, and dropping it would
 * under-report the diff.
 */
type OrphanChange = TreeModel["orphanChanges"][number];
type DiffRow = { kind: "node"; row: Row } | { kind: "orphan"; change: OrphanChange };

/** The descendant-change rollup shown on an unchanged ancestor. */
function DescendantChanges(props: { row: Row }) {
    const d = () => props.row.node.descendantChanges;
    return (
        <span class="badge-row">
            <Show when={(d()?.upgraded ?? 0) > 0}>
                <span class="badge badge-primary badge-sm">↑{d()?.upgraded}</span>
            </Show>
            <Show when={(d()?.downgraded ?? 0) > 0}>
                <span class="badge badge-warning badge-sm">↓{d()?.downgraded}</span>
            </Show>
            <Show when={(d()?.added ?? 0) > 0}>
                <span class="badge badge-primary badge-sm">+{d()?.added}</span>
            </Show>
            <Show when={(d()?.removed ?? 0) > 0}>
                <span class="badge badge-warning badge-sm">-{d()?.removed}</span>
            </Show>
            <Show when={(d()?.modified ?? 0) > 0}>
                <span class="badge badge-sm">~{d()?.modified}</span>
            </Show>
        </span>
    );
}

function VersionChange(props: { previous?: string; current?: string }) {
    return (
        <>
            <Show when={props.previous}>
                <span class="text-muted">{props.previous}</span>
                {" → "}
            </Show>
            {props.current ?? <span class="text-muted">—</span>}
        </>
    );
}

export function DiffTreeView(props: { tree: DiffTree; hideHeader?: boolean }) {
    const treeData = createMemo(() => buildTreeModel(props.tree));

    const [expandedRefs, setExpandedRefs] = createSignal(new Set<string>(), { equals: false });
    const [showContext,    setShowContext]    = createLocalStorageSignal("ocidex.diff.showContext", false);
    const [showTransitive, setShowTransitive] = createLocalStorageSignal("ocidex.diff.showTransitive", false);

    const toggleExpanded = (ref: string) => {
        setExpandedRefs(s => {
            const next = new Set(s);
            if (next.has(ref)) next.delete(ref); else next.add(ref);
            return next;
        });
    };

    const expandAllChanged = () => {
        const { nodes } = treeData();
        const toExpand = new Set<string>();
        for (const [ref, node] of nodes) {
            if (node.hasChangedDesc) toExpand.add(ref);
        }
        setExpandedRefs(() => toExpand);
    };

    // A change under an unexpanded ancestor is counted in the header and rendered
    // nowhere, which reads as "↑1 upgraded" over an empty table. Expanding the
    // ancestors of every change on mount (and again whenever a new tree arrives)
    // makes the default view self-consistent. Safe as an effect: expandAllChanged
    // reads treeData but never expandedRefs, so this can't loop.
    createEffect(() => {
        treeData();
        expandAllChanged();
    });

    const visibleRows = createMemo((): Row[] =>
        flattenVisibleRows(treeData(), {
            expanded: expandedRefs(),
            showContext: showContext(),
            showTransitive: showTransitive(),
        }),
    );

    // Every change the tree renders, counted by distinct node so a diamond
    // dependency rendered under two parents still counts once.
    const renderedChangeIDs = createMemo(() => {
        const ids = new Set<string>();
        for (const row of visibleRows()) {
            if (row.node.changeKind !== undefined) ids.add(row.node.id ?? row.node.ref);
        }
        return ids;
    });

    const shownChangeCount  = () => renderedChangeIDs().size + treeData().orphanChanges.length;
    const hiddenChangeCount = () => Math.max(0, changes().length - shownChangeCount());

    const revealHidden = () => {
        setShowTransitive(true);
        expandAllChanged();
    };

    // Summary counts for the header badges.
    const changes = () => treeData().changes;
    const addedCount   = () => changes().filter((c) => c.type === "added").length;
    const removedCount = () => changes().filter((c) => c.type === "removed").length;
    const upgradedCount   = () => changes().filter((c) => c.direction === "upgraded").length;
    const downgradedCount = () => changes().filter((c) => c.direction === "downgraded").length;

    const kindDefs = [
        { count: addedCount,      cls: "badge-primary",  fmt: (n: number) => `+${n} added` },
        { count: removedCount,    cls: "badge-warning",  fmt: (n: number) => `-${n} removed` },
        { count: upgradedCount,   cls: "badge-primary",  fmt: (n: number) => `↑${n} upgraded` },
        { count: downgradedCount, cls: "badge-warning",  fmt: (n: number) => `↓${n} downgraded` },
    ];

    const rows = (): DiffRow[] => [
        ...visibleRows().map((row): DiffRow => ({ kind: "node", row })),
        ...treeData().orphanChanges.map((change): DiffRow => ({ kind: "orphan", change })),
    ];

    const columns = (): Column<DiffRow>[] => [
        {
            header: "Package",
            render: (r) =>
                r.kind === "orphan" ? (
                    // No twisty and no depth, but the same left gutter as a
                    // root row, so orphans line up with the tree above them.
                    <span class="tree-name font-mono text-sm">
                        <span class="tree-twisty" />
                        {r.change.group !== undefined && r.change.group !== ""
                            ? `${r.change.group}/`
                            : ""}
                        {r.change.name}
                    </span>
                ) : (
                    <span class="tree-name" style={{ "--depth": r.row.depth }}>
                        <span
                            class="tree-twisty"
                            classList={{
                                open:
                                    r.row.relevantChildCount > 0 &&
                                    expandedRefs().has(r.row.node.ref),
                            }}
                        >
                            {r.row.relevantChildCount > 0 ? "▸" : ""}
                        </span>
                        <Show
                            when={r.row.node.id}
                            keyed
                            fallback={<span class="font-mono text-sm">{r.row.node.name}</span>}
                        >
                            {(id) => (
                                <A
                                    href={`/components/${id}`}
                                    class="font-mono text-sm"
                                    onClick={(e: MouseEvent) => e.stopPropagation()}
                                >
                                    {r.row.node.name}
                                </A>
                            )}
                        </Show>
                    </span>
                ),
        },
        {
            header: "Change",
            render: (r) =>
                r.kind === "orphan" ? (
                    <span class={changeBadgeClass(r.change.direction)}>
                        {r.change.direction !== "" ? r.change.direction : r.change.type}
                    </span>
                ) : r.row.node.changeKind !== undefined ? (
                    <span class={changeBadgeClass(r.row.node.changeKind)}>
                        {r.row.node.changeKind}
                    </span>
                ) : (
                    <Show when={r.row.node.hasChangedDesc}>
                        <DescendantChanges row={r.row} />
                    </Show>
                ),
        },
        {
            header: "Version",
            class: "font-mono text-sm",
            render: (r) =>
                r.kind === "orphan" ? (
                    <VersionChange
                        previous={r.change.previousVersion}
                        current={r.change.version}
                    />
                ) : (
                    <VersionChange
                        previous={r.row.node.previousVersion}
                        current={r.row.node.version}
                    />
                ),
        },
    ];

    return (
        <div class="changelog-entry">
            <Show when={props.hideHeader !== true}>
                <div class="changelog-entry-header">
                    <div class="text-sm">
                        <A href={`/sboms/${props.tree.from.id}`} class="font-mono">
                            {changelogRefLabel(props.tree.from)}
                        </A>
                        {" → "}
                        <A href={`/sboms/${props.tree.to.id}`} class="font-mono">
                            {changelogRefLabel(props.tree.to)}
                        </A>
                        <span class="text-muted">
                            {" "}
                            ({relativeDate(props.tree.to.buildDate ?? props.tree.to.createdAt)})
                        </span>
                    </div>
                    <div class="changelog-summary">
                        <For each={kindDefs}>
                            {(k) => (
                                <Show when={k.count() > 0}>
                                    <span class={`badge ${k.cls}`}>{k.fmt(k.count())}</span>
                                </Show>
                            )}
                        </For>
                    </div>
                </div>
            </Show>
            <div style={{ display: "flex", gap: "0.75rem", "align-items": "center", padding: "0.5rem 0", "flex-wrap": "wrap" }}>
                <Button
                    size="sm"
                    title="Expand every branch that contains a changed package"
                    onClick={expandAllChanged}
                >
                    Expand all changed
                </Button>
                <label
                    title="Include unchanged ancestors of changed packages so you can see where each change lives in the tree. Off by default — only changed packages and their changed descendants are shown."
                    style={{ display: "flex", gap: "0.35rem", "align-items": "center", "font-size": "0.85rem", cursor: "pointer" }}
                >
                    <input
                        type="checkbox"
                        checked={showContext()}
                        onChange={(e) => setShowContext(e.currentTarget.checked)}
                    />
                    Show context
                </label>
                <label
                    title="Include indirect (transitive) dependencies. Off by default — only direct dependencies of the image's metadata.component are shown, with their changed descendants. Turn on to see deeper dependency chains."
                    style={{ display: "flex", gap: "0.35rem", "align-items": "center", "font-size": "0.85rem", cursor: "pointer" }}
                >
                    <input
                        type="checkbox"
                        checked={showTransitive()}
                        onChange={(e) => setShowTransitive(e.currentTarget.checked)}
                    />
                    Show transitive
                </label>
            </div>
            <Show when={hiddenChangeCount() > 0}>
                <p class="text-muted text-sm" style={{ padding: "0 0 0.5rem" }}>
                    Showing {shownChangeCount()} of {changes().length} changes —{" "}
                    {hiddenChangeCount()} hidden under indirect dependencies.{" "}
                    <Button size="sm" onClick={revealHidden}>
                        Show hidden changes
                    </Button>
                </p>
            </Show>
            <Show
                when={treeData().roots.length > 0 || treeData().orphanChanges.length > 0}
                fallback={
                    <p class="text-muted text-sm" style={{ padding: "1rem 0" }}>
                        No dependency tree available for this diff. Switch to list view to see all changes.
                    </p>
                }
            >
                <DataTable
                    bare
                    // The indentation *is* the containment relation; a card
                    // stack throws it away and leaves a flat list of names.
                    mobileLayout="scroll"
                    columns={columns()}
                    rows={rows()}
                    loading={false}
                    isError={false}
                    emptyTitle="No changes"
                    rowClass={(r) =>
                        r.kind === "node" && r.row.node.changeKind === undefined
                            ? "row-muted"
                            : undefined
                    }
                    rowClickable={(r) => r.kind === "node" && r.row.relevantChildCount > 0}
                    onRowClick={(r) => {
                        if (r.kind === "node") toggleExpanded(r.row.node.ref);
                    }}
                />
            </Show>
        </div>
    );
}
