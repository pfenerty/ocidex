import { createSignal, createMemo, Show, For, untrack } from "solid-js";
import { A } from "@solidjs/router";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import PurlLink from "~/components/PurlLink";
import { plural } from "~/utils/format";
import { parsePurl } from "~/utils/purl";

/* ------------------------------------------------------------------ */
/*  Packages Tab                                                       */
/* ------------------------------------------------------------------ */

export function PackagesTab(props: { components: ComponentSummary[] }) {
    const [filter, setFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("all");
    const [page, setPage] = createSignal(0);
    const pageSize = 50;

    const ecoType = (c: ComponentSummary) =>
        parsePurl(c.purl ?? "")?.type ?? c.type;

    // Exclude "file" type components from the entire view
    const packages = createMemo(() =>
        props.components.filter((c) => c.type !== "file"),
    );

    const types = createMemo(() => {
        const set = new Set(packages().map(ecoType));
        return Array.from(set).sort();
    });

    const filtered = createMemo(() => {
        const comps = packages();
        if (comps.length === 0) return [];
        const q = filter().toLowerCase();
        const t = typeFilter();
        return comps.filter((c) => {
            if (t !== "all" && ecoType(c) !== t) return false;
            if (!q) return true;
            const display =
                (c.group !== undefined && c.group !== "" ? `${c.group}/` : "") +
                c.name +
                (c.version !== undefined && c.version !== "" ? `@${c.version}` : "");
            return (
                display.toLowerCase().includes(q) ||
                (c.purl?.toLowerCase().includes(q) ?? false)
            );
        });
    });

    const pageCount = () =>
        Math.max(1, Math.ceil(filtered().length / pageSize));
    const paged = () =>
        filtered().slice(page() * pageSize, (page() + 1) * pageSize);

    // Reset page when filter changes
    const updateFilter = (v: string) => {
        setFilter(v);
        setPage(0);
    };
    const updateType = (v: string) => {
        setTypeFilter(v);
        setPage(0);
    };

    return (
        <Show
            when={packages().length > 0}
            fallback={
                <EmptyState
                    title="No packages"
                    message="This SBOM has no components."
                />
            }
        >
            <div class="card">
                <div class="search-bar mb-md" style={{ "flex-wrap": "wrap" }}>
                    <input
                        type="text"
                        placeholder="Filter packages…"
                        value={filter()}
                        onInput={(e) => updateFilter(e.currentTarget.value)}
                        style={{ flex: "1", "min-width": "200px" }}
                    />
                    <select
                        value={typeFilter()}
                        onChange={(e) => updateType(e.currentTarget.value)}
                    >
                        <option value="all">
                            All types ({packages().length})
                        </option>
                        <For each={types()}>
                            {(t) => <option value={t}>{t}</option>}
                        </For>
                    </select>
                    <span class="text-muted text-sm">
                        {filtered().length === packages().length
                            ? plural(filtered().length, "package")
                            : `${filtered().length} of ${packages().length} packages`}
                    </span>
                </div>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Version</th>
                                <th>Type</th>
                                <th>Package URL</th>
                                <th />
                            </tr>
                        </thead>
                        <tbody>
                            <For each={paged()}>
                                {(c) => (
                                    <tr>
                                        <td>
                                            <A href={`/components/${c.id}`}>
                                                {c.group !== undefined && c.group !== "" ? `${c.group}/` : ""}
                                                {c.name}
                                            </A>
                                        </td>
                                        <td class="mono">
                                            {c.version ?? (
                                                <span class="text-muted">
                                                    —
                                                </span>
                                            )}
                                        </td>
                                        <td>
                                            <span class="badge">
                                                {parsePurl(c.purl ?? "")?.type ?? c.type}
                                            </span>
                                        </td>
                                        <td class="truncate">
                                            <Show
                                                when={c.purl}
                                                fallback={
                                                    <span class="text-muted">
                                                        —
                                                    </span>
                                                }
                                                keyed
                                            >
                                                {(purl) => (
                                                    <PurlLink
                                                        purl={purl}
                                                        showBadge
                                                    />
                                                )}
                                            </Show>
                                        </td>
                                        <td>
                                            <A
                                                href={`/components/${c.id}`}
                                                class="text-sm"
                                            >
                                                Details →
                                            </A>
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>

                <Show when={pageCount() > 1}>
                    <div class="pagination">
                        <span>
                            Page {page() + 1} of {pageCount()}
                        </span>
                        <div class="pagination-controls">
                            <button
                                disabled={page() === 0}
                                onClick={() => setPage(page() - 1)}
                            >
                                ← Prev
                            </button>
                            <button
                                disabled={page() >= pageCount() - 1}
                                onClick={() => setPage(page() + 1)}
                            >
                                Next →
                            </button>
                        </div>
                    </div>
                </Show>
            </div>
        </Show>
    );
}

/* ------------------------------------------------------------------ */
/*  Dependencies Tab – expandable tree                                 */
/* ------------------------------------------------------------------ */

interface TreeNode {
    ref: string;
    label: string;
    id?: string;
    purl?: string;
    children: string[];
}

export function DependencyTreeView(props: {
    graph: { edges: DependencyEdge[]; nodes: ComponentSummary[] };
}) {
    // Build adjacency list and name map
    const treeData = createMemo(() => {
        const adj = new Map<string, string[]>();
        const allTargets = new Set<string>();

        for (const edge of props.graph.edges) {
            if (!adj.has(edge.from)) adj.set(edge.from, []);
            adj.get(edge.from)?.push(edge.to);
            allTargets.add(edge.to);
        }

        // Name lookup: ref -> display label & component id
        const nameMap = new Map<
            string,
            { label: string; id?: string; purl?: string }
        >();
        for (const node of props.graph.nodes) {
            const label = node.group !== undefined && node.group !== "" ? `${node.group}/${node.name}` : node.name;
            const display = node.version !== undefined && node.version !== "" ? `${label}@${node.version}` : label;
            const info = { label: display, id: node.id, purl: node.purl };
            nameMap.set(node.id, info);
            nameMap.set(node.name, info);
            if (node.purl !== undefined) nameMap.set(node.purl, info);
            if (node.bomRef !== undefined) nameMap.set(node.bomRef, info);
        }

        // Find root nodes
        const fromRefs = [...adj.keys()];
        let rootRefs = fromRefs.filter((r) => !allTargets.has(r));
        if (rootRefs.length === 0) rootRefs = fromRefs.slice(0, 10);

        // Build TreeNode map for all refs
        const allRefs = new Set([...adj.keys(), ...allTargets]);
        const nodes = new Map<string, TreeNode>();
        for (const ref of allRefs) {
            const info = nameMap.get(ref);
            nodes.set(ref, {
                ref,
                label: info?.label ?? ref,
                id: info?.id,
                purl: info?.purl,
                children: adj.get(ref) ?? [],
            });
        }

        return {
            roots: rootRefs,
            nodes,
            edgeCount: props.graph.edges.length,
            nodeCount: props.graph.nodes.length,
        };
    });

    return (
        <div class="card">
            <div class="card-header">
                <span class="text-sm text-muted">
                    {plural(treeData().nodeCount, "component")},{" "}
                    {plural(treeData().edgeCount, "dependency edge")}
                </span>
            </div>
            <div
                style={{
                    "max-height": "600px",
                    "overflow-y": "auto",
                    padding: "0.5rem 0",
                }}
            >
                <For each={treeData().roots}>
                    {(rootRef) => {
                        const node = treeData().nodes.get(rootRef);
                        return node ? (
                            <TreeNodeRow
                                node={node}
                                allNodes={treeData().nodes}
                                depth={0}
                                visited={new Set()}
                            />
                        ) : null;
                    }}
                </For>
            </div>
        </div>
    );
}

function TreeNodeRow(props: {
    node: TreeNode;
    allNodes: Map<string, TreeNode>;
    depth: number;
    visited: Set<string>;
}) {
    const [expanded, setExpanded] = createSignal(untrack(() => props.depth === 0));
    const hasChildren = () => props.node.children.length > 0;
    const isCyclic = () => props.visited.has(props.node.ref);

    const childNodes = createMemo(() => {
        if (!expanded() || isCyclic()) return [];
        return props.node.children
            .map((ref) => props.allNodes.get(ref))
            .filter((n): n is TreeNode => !!n);
    });

    const nextVisited = createMemo(() => {
        const s = new Set(props.visited);
        s.add(props.node.ref);
        return s;
    });

    return (
        <>
            <div
                class="dep-tree-row"
                style={{
                    "padding-left": `${props.depth * 1.25 + 0.75}rem`,
                    display: "flex",
                    "align-items": "center",
                    gap: "0.375rem",
                    padding: `0.3rem 0.75rem 0.3rem ${props.depth * 1.25 + 0.75}rem`,
                    "font-size": "0.85rem",
                    "border-bottom": "1px solid var(--color-border)",
                    cursor: hasChildren() ? "pointer" : "default",
                }}
                onClick={() => hasChildren() && setExpanded(!expanded())}
            >
                {/* Toggle icon */}
                <span
                    style={{
                        width: "1rem",
                        "text-align": "center",
                        color: "var(--color-text-dim)",
                        "font-size": "0.7rem",
                        "flex-shrink": "0",
                        transition: "transform 0.15s",
                        transform:
                            hasChildren() && expanded()
                                ? "rotate(90deg)"
                                : "rotate(0deg)",
                    }}
                >
                    {hasChildren() ? "▸" : " "}
                </span>

                {/* Label */}
                <Show
                    when={props.node.id}
                    fallback={
                        <span
                            class="mono"
                            style={{ color: "var(--color-text-muted)" }}
                        >
                            {props.node.label}
                        </span>
                    }
                >
                    <A
                        href={`/components/${props.node.id}`}
                        class="mono"
                        style={{ "font-size": "0.85rem" }}
                        onClick={(e: Event) => e.stopPropagation()}
                    >
                        {props.node.label}
                    </A>
                </Show>

                {/* Dep count badge */}
                <Show when={hasChildren()}>
                    <span
                        class="badge badge-sm"
                        style={{ "margin-left": "0.25rem" }}
                    >
                        {props.node.children.length}
                    </span>
                </Show>

                {/* Cycle indicator */}
                <Show when={isCyclic()}>
                    <span
                        class="badge badge-warning"
                        style={{
                            "font-size": "0.65rem",
                            "margin-left": "0.25rem",
                        }}
                    >
                        circular
                    </span>
                </Show>
            </div>

            {/* Render children */}
            <Show when={expanded() && !isCyclic()}>
                <For each={childNodes()}>
                    {(child) => (
                        <TreeNodeRow
                            node={child}
                            allNodes={props.allNodes}
                            depth={props.depth + 1}
                            visited={nextVisited()}
                        />
                    )}
                </For>
            </Show>
        </>
    );
}
