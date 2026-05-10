import { createMemo, createSignal, Show, For } from "solid-js";
import { createLocalStorageSignal } from "~/utils/prefs";
import { A } from "@solidjs/router";
import { relativeDate } from "~/utils/format";
import { changelogRefLabel } from "~/utils/diff";
import type { DiffTree } from "~/api/client";
import { parsePurl } from "~/utils/purl";

interface TreeNode {
    ref: string;
    name: string;
    version?: string;
    previousVersion?: string;
    purl?: string;
    id?: string;
    changeKind?: string;
    children: string[];
    hasChangedDesc: boolean;
    isDirect: boolean;
    descendantChanges?: { added: number; removed: number; upgraded: number; downgraded: number; modified: number };
}

interface Row {
    node: TreeNode;
    depth: number;
    relevantChildCount: number;
}

function purlBase(purl: string): string {
    const atIdx = purl.indexOf("@");
    return atIdx > 0 ? purl.slice(0, atIdx) : purl.split("?")[0];
}

export function DiffTreeView(props: { tree: DiffTree }) {
    const treeData = createMemo(() => {
        // Filter to non-file changes once; we use this set for the orphan list and for
        // joining changes onto nodes via change.nodeRef (set by the backend per ADR-0021 §B3).
        const filteredChanges = (props.tree.changes ?? []).filter(
            (c) => c.purl !== undefined && parsePurl(c.purl)?.type !== "file",
        );
        const changeByNodeRef = new Map<string, typeof filteredChanges[number]>();
        for (const c of filteredChanges) {
            if (c.nodeRef !== undefined && c.nodeRef !== "") changeByNodeRef.set(c.nodeRef, c);
        }

        // Build adjacency from edges. Membership in the tree comes from props.tree.nodes
        // (server-authoritative per ADR-0021), not the edge set — disconnected roots
        // (zero in-edges, zero out-edges) must still render.
        const adj = new Map<string, string[]>();
        for (const edge of props.tree.edges ?? []) {
            if (!adj.has(edge.from)) adj.set(edge.from, []);
            adj.get(edge.from)?.push(edge.to);
        }

        // Build the TreeNode map keyed on bomRef directly from props.tree.nodes.
        const nodes = new Map<string, TreeNode>();
        const inGraphPurls = new Set<string>();
        for (const node of props.tree.nodes ?? []) {
            const type = parsePurl(node.purl ?? "")?.type ?? node.type;
            if (type === "file") continue;
            if (node.bomRef === undefined || node.bomRef === "") continue;

            const displayName =
                node.group !== undefined && node.group !== ""
                    ? `${node.group}/${node.name}`
                    : node.name;
            const change = changeByNodeRef.get(node.id);
            const dc = node.descendantChanges;
            const hasChangedDesc =
                dc !== undefined &&
                dc.added + dc.removed + dc.upgraded + dc.downgraded + dc.modified > 0;

            nodes.set(node.bomRef, {
                ref: node.bomRef,
                name: displayName,
                version: change?.version ?? (node.version !== "" ? node.version : undefined),
                previousVersion: change?.previousVersion,
                purl: node.purl !== "" ? node.purl : undefined,
                id: node.id,
                changeKind: change?.direction,
                children: adj.get(node.bomRef) ?? [],
                hasChangedDesc,
                isDirect: node.isDirect,
                descendantChanges: dc ?? undefined,
            });

            if (node.purl !== undefined && node.purl !== "") {
                inGraphPurls.add(node.purl);
                inGraphPurls.add(purlBase(node.purl));
            }
        }

        // Use backend-computed roots (anchored on metadata.component.bom-ref per ADR-0021 §B5).
        const rootRefs = props.tree.roots ?? [];

        // Removed packages with no node in the graph — surfaced separately so the user
        // doesn't lose them, since by definition they have no tree position.
        const removedOrphans = filteredChanges.filter((c) => {
            if (c.direction !== "removed") return false;
            if (c.purl !== undefined && (inGraphPurls.has(c.purl) || inGraphPurls.has(purlBase(c.purl)))) return false;
            return true;
        });

        return { roots: rootRefs, nodes, removedOrphans };
    });

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

    // DFS over roots → flat array of visible rows in traversal order.
    // pathSet tracks ancestors on the current path for cycle detection (same semantics as the
    // former nextVisited prop cascade — a node is cyclic only if it appears in its own ancestry).
    const visibleRows = createMemo((): Row[] => {
        const { roots, nodes } = treeData();
        const expanded = expandedRefs();
        const result: Row[] = [];
        const pathSet = new Set<string>();

        const ctx = showContext();
        const transitive = showTransitive();

        function visit(ref: string, depth: number, inChangedDirectSubtree: boolean) {
            if (pathSet.has(ref)) return;
            const node = nodes.get(ref);
            if (!node) return;
            if (node.changeKind === undefined && node.purl === undefined) return;
            if (!ctx && node.changeKind === undefined && !node.hasChangedDesc) return;
            if (!transitive && !node.isDirect && !inChangedDirectSubtree && node.changeKind === undefined) return;

            const relevantChildren = node.children.filter((childRef) => {
                const child = nodes.get(childRef);
                return child !== undefined && (child.changeKind !== undefined || child.hasChangedDesc);
            });

            result.push({ node, depth, relevantChildCount: relevantChildren.length });

            if (expanded.has(ref)) {
                pathSet.add(ref);
                const childInChangedDirect = inChangedDirectSubtree || (node.isDirect && node.changeKind !== undefined);
                for (const childRef of relevantChildren) visit(childRef, depth + 1, childInChangedDirect);
                pathSet.delete(ref);
            }
        }

        for (const rootRef of roots) visit(rootRef, 0, false);
        return result;
    });

    // Summary counts for the header badges.
    const changes = () => (props.tree.changes ?? []).filter(
        (c) => c.purl !== undefined && parsePurl(c.purl)?.type !== "file",
    );
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

    return (
        <div class="changelog-entry">
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
            <div style={{ display: "flex", gap: "0.75rem", "align-items": "center", padding: "0.5rem 0", "flex-wrap": "wrap" }}>
                <button
                    class="btn btn-sm"
                    onClick={expandAllChanged}
                >
                    Expand all changed
                </button>
                <label style={{ display: "flex", gap: "0.35rem", "align-items": "center", "font-size": "0.85rem", cursor: "pointer" }}>
                    <input
                        type="checkbox"
                        checked={showContext()}
                        onChange={(e) => setShowContext(e.currentTarget.checked)}
                    />
                    Show context
                </label>
                <label style={{ display: "flex", gap: "0.35rem", "align-items": "center", "font-size": "0.85rem", cursor: "pointer" }}>
                    <input
                        type="checkbox"
                        checked={showTransitive()}
                        onChange={(e) => setShowTransitive(e.currentTarget.checked)}
                    />
                    Show transitive
                </label>
            </div>
            <Show
                when={treeData().roots.length > 0 || treeData().removedOrphans.length > 0}
                fallback={
                    <p class="text-muted text-sm" style={{ padding: "1rem 0" }}>
                        No dependency tree available for this diff. Switch to list view to see all changes.
                    </p>
                }
            >
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Package</th>
                                <th>Change</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={visibleRows()}>
                                {(row) => {
                                    const isExpanded = () => expandedRefs().has(row.node.ref);
                                    const isChanged = () => row.node.changeKind !== undefined;
                                    const changeCls = () => {
                                        const k = row.node.changeKind;
                                        if (k === "added" || k === "upgraded") return "badge-primary";
                                        if (k === "removed" || k === "downgraded") return "badge-warning";
                                        return "";
                                    };
                                    return (
                                        <tr
                                            style={{
                                                cursor: row.relevantChildCount > 0 ? "pointer" : "default",
                                                opacity: isChanged() ? "1" : "0.55",
                                            }}
                                            onClick={() => row.relevantChildCount > 0 && toggleExpanded(row.node.ref)}
                                        >
                                            <td>
                                                <span
                                                    style={{
                                                        display: "flex",
                                                        "align-items": "center",
                                                        gap: "0.375rem",
                                                        "padding-left": `${row.depth * 1.25}rem`,
                                                    }}
                                                >
                                                    <span
                                                        style={{
                                                            width: "1rem",
                                                            "text-align": "center",
                                                            color: "var(--color-text-dim)",
                                                            "font-size": "0.7rem",
                                                            "flex-shrink": "0",
                                                            transition: "transform 0.15s",
                                                            transform:
                                                                row.relevantChildCount > 0 && isExpanded()
                                                                    ? "rotate(90deg)"
                                                                    : "rotate(0deg)",
                                                        }}
                                                    >
                                                        {row.relevantChildCount > 0 ? "▸" : ""}
                                                    </span>
                                                    <Show
                                                        when={row.node.id}
                                                        keyed
                                                        fallback={
                                                            <span
                                                                class="font-mono"
                                                                style={{ "font-size": "0.85rem" }}
                                                            >
                                                                {row.node.name}
                                                            </span>
                                                        }
                                                    >
                                                        {(id) => (
                                                            <A
                                                                href={`/components/${id}`}
                                                                class="font-mono"
                                                                style={{ "font-size": "0.85rem" }}
                                                                onClick={(e: MouseEvent) =>
                                                                    e.stopPropagation()
                                                                }
                                                            >
                                                                {row.node.name}
                                                            </A>
                                                        )}
                                                    </Show>
                                                </span>
                                            </td>
                                            <td>
                                                <Show when={isChanged()}>
                                                    <span class={`badge ${changeCls()}`}>
                                                        {row.node.changeKind}
                                                    </span>
                                                </Show>
                                                <Show when={!isChanged() && row.node.hasChangedDesc}>
                                                    <span style={{ display: "flex", gap: "0.25rem", "flex-wrap": "wrap" }}>
                                                        <Show when={(row.node.descendantChanges?.upgraded ?? 0) > 0}>
                                                            <span class="badge badge-primary badge-sm">↑{row.node.descendantChanges?.upgraded}</span>
                                                        </Show>
                                                        <Show when={(row.node.descendantChanges?.downgraded ?? 0) > 0}>
                                                            <span class="badge badge-warning badge-sm">↓{row.node.descendantChanges?.downgraded}</span>
                                                        </Show>
                                                        <Show when={(row.node.descendantChanges?.added ?? 0) > 0}>
                                                            <span class="badge badge-primary badge-sm">+{row.node.descendantChanges?.added}</span>
                                                        </Show>
                                                        <Show when={(row.node.descendantChanges?.removed ?? 0) > 0}>
                                                            <span class="badge badge-warning badge-sm">-{row.node.descendantChanges?.removed}</span>
                                                        </Show>
                                                        <Show when={(row.node.descendantChanges?.modified ?? 0) > 0}>
                                                            <span class="badge badge-sm">~{row.node.descendantChanges?.modified}</span>
                                                        </Show>
                                                    </span>
                                                </Show>
                                            </td>
                                            <td class="font-mono" style={{ "font-size": "0.85rem" }}>
                                                <Show when={row.node.previousVersion}>
                                                    <span class="text-muted">{row.node.previousVersion}</span>
                                                    {" → "}
                                                </Show>
                                                {row.node.version ?? (
                                                    <span class="text-muted">—</span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                }}
                            </For>
                            <Show when={treeData().removedOrphans.length > 0}>
                                <For each={treeData().removedOrphans}>
                                    {(c) => (
                                        <tr>
                                            <td>
                                                <span
                                                    class="font-mono"
                                                    style={{
                                                        "font-size": "0.85rem",
                                                        "padding-left": "1.375rem",
                                                        display: "block",
                                                    }}
                                                >
                                                    {c.group !== undefined && c.group !== ""
                                                        ? `${c.group}/`
                                                        : ""}
                                                    {c.name}
                                                </span>
                                            </td>
                                            <td>
                                                <span class="badge badge-warning">
                                                    removed
                                                </span>
                                            </td>
                                            <td class="font-mono" style={{ "font-size": "0.85rem" }}>
                                                <span class="text-muted">
                                                    {c.previousVersion ?? "—"}
                                                </span>
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </Show>
                        </tbody>
                    </table>
                </div>
            </Show>
        </div>
    );
}
