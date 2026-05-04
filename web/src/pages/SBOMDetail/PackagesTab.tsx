import { createSignal, createMemo, Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import PurlLink from "~/components/PurlLink";
import { plural } from "~/utils/format";
import { parsePurl } from "~/utils/purl";

/* ------------------------------------------------------------------ */
/*  Packages Tab                                                       */
/* ------------------------------------------------------------------ */

export function PackagesTab(props: {
    components: ComponentSummary[];
    depsGraph?: { edges: DependencyEdge[]; nodes: ComponentSummary[] };
}) {
    const [filter, setFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("all");
    const [page, setPage] = createSignal(0);
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");
    const [showPlanFiles, setShowPlanFiles] = createSignal(false);
    const pageSize = 50;

    const ecoType = (c: ComponentSummary) =>
        parsePurl(c.purl ?? "")?.type ?? c.type;

    const packages = createMemo(() =>
        showPlanFiles()
            ? props.components
            : props.components.filter((c) => c.type !== "file"),
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

    const updateFilter = (v: string) => {
        setFilter(v);
        setPage(0);
    };
    const updateType = (v: string) => {
        setTypeFilter(v);
        setPage(0);
    };

    const hasTree = () => (props.depsGraph?.edges.length ?? 0) > 0;
    const effectiveMode = () => (hasTree() ? viewMode() : "list");

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
                    <Show when={effectiveMode() === "list"}>
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
                    </Show>
                    <span class="text-muted text-sm">
                        {effectiveMode() === "list"
                            ? filtered().length === packages().length
                                ? plural(filtered().length, "package")
                                : `${filtered().length} of ${packages().length} packages`
                            : plural(packages().length, "package")}
                    </span>
                    <label style={{ display: "flex", "align-items": "center", gap: "6px", cursor: "pointer", "font-size": "0.875rem" }}>
                        <input
                            type="checkbox"
                            checked={showPlanFiles()}
                            onChange={(e) => setShowPlanFiles(e.target.checked)}
                        />
                        Show plan files
                    </label>
                    <Show when={hasTree()}>
                        <div class="btn-group" style={{ "margin-left": "auto" }}>
                            <button
                                class={`btn btn-sm${effectiveMode() === "tree" ? " active" : ""}`}
                                onClick={() => setViewMode("tree")}
                            >
                                Tree
                            </button>
                            <button
                                class={`btn btn-sm${effectiveMode() === "list" ? " active" : ""}`}
                                onClick={() => setViewMode("list")}
                            >
                                List
                            </button>
                        </div>
                    </Show>
                </div>

                <Show
                    when={effectiveMode() === "tree" ? props.depsGraph : undefined}
                    keyed
                    fallback={
                        <>
                            <div class="table-wrapper">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>Version</th>
                                            <th>Type</th>
                                            <th>Package URL</th>
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
                        </>
                    }
                >
                    {(graph) => <DependencyTreeView graph={graph} showPlanFiles={showPlanFiles()} />}
                </Show>
            </div>
        </Show>
    );
}

/* ------------------------------------------------------------------ */
/*  Dependency Tree View – simple table, lazy-mount on expand         */
/* ------------------------------------------------------------------ */

interface TreeNode {
    ref: string;
    name: string;
    version?: string;
    type?: string;
    id?: string;
    purl?: string;
    children: string[];
}

export function DependencyTreeView(props: {
    graph: { edges: DependencyEdge[]; nodes: ComponentSummary[] };
    showPlanFiles?: boolean;
}) {
    const treeData = createMemo(() => {
        const nameMap = new Map<
            string,
            { name: string; version?: string; type?: string; id?: string; purl?: string }
        >();
        for (const node of props.graph.nodes) {
            const name =
                node.group !== undefined && node.group !== ""
                    ? `${node.group}/${node.name}`
                    : node.name;
            const version =
                node.version !== undefined && node.version !== ""
                    ? node.version
                    : undefined;
            const type = parsePurl(node.purl ?? "")?.type ?? node.type;
            const info = { name, version, type, id: node.id, purl: node.purl };
            nameMap.set(node.id, info);
            nameMap.set(node.name, info);
            if (node.purl !== undefined) nameMap.set(node.purl, info);
            if (node.bomRef !== undefined) nameMap.set(node.bomRef, info);
        }

        const edges = props.showPlanFiles === true
            ? props.graph.edges
            : props.graph.edges.filter(
                (e) =>
                    nameMap.get(e.from)?.type !== "file" &&
                    nameMap.get(e.to)?.type !== "file",
            );

        const adj = new Map<string, string[]>();
        const allTargets = new Set<string>();

        for (const edge of edges) {
            if (!adj.has(edge.from)) adj.set(edge.from, []);
            adj.get(edge.from)?.push(edge.to);
            allTargets.add(edge.to);
        }

        const fromRefs = [...adj.keys()];
        let rootRefs = fromRefs.filter((r) => !allTargets.has(r));
        if (rootRefs.length === 0) rootRefs = fromRefs.slice(0, 10);

        const allRefs = new Set([...adj.keys(), ...allTargets]);
        const nodes = new Map<string, TreeNode>();
        for (const ref of allRefs) {
            const info = nameMap.get(ref);
            nodes.set(ref, {
                ref,
                name: info?.name ?? ref,
                version: info?.version,
                type: info?.type,
                id: info?.id,
                purl: info?.purl,
                children: adj.get(ref) ?? [],
            });
        }

        return { roots: rootRefs, nodes };
    });

    return (
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Package URL</th>
                    </tr>
                </thead>
                <tbody>
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
                </tbody>
            </table>
        </div>
    );
}

function TreeNodeRow(props: {
    node: TreeNode;
    allNodes: Map<string, TreeNode>;
    depth: number;
    visited: Set<string>;
}) {
    const [expanded, setExpanded] = createSignal(false);
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
            <tr
                style={{
                    cursor:
                        hasChildren() && !isCyclic() ? "pointer" : "default",
                }}
                onClick={() =>
                    hasChildren() && !isCyclic() && setExpanded(!expanded())
                }
            >
                <td>
                    <span
                        style={{
                            display: "flex",
                            "align-items": "center",
                            gap: "0.375rem",
                            "padding-left": `${props.depth * 1.25}rem`,
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
                                    hasChildren() &&
                                    !isCyclic() &&
                                    expanded()
                                        ? "rotate(90deg)"
                                        : "rotate(0deg)",
                            }}
                        >
                            {hasChildren() && !isCyclic() ? "▸" : ""}
                        </span>
                        <Show
                            when={props.node.id}
                            keyed
                            fallback={
                                <span
                                    class="mono"
                                    style={{
                                        "font-size": "0.85rem",
                                        color: "var(--color-text-muted)",
                                    }}
                                >
                                    {props.node.name}
                                </span>
                            }
                        >
                            {(id) => (
                                <A
                                    href={`/components/${id}`}
                                    class="mono"
                                    style={{ "font-size": "0.85rem" }}
                                    onClick={(e: MouseEvent) =>
                                        e.stopPropagation()
                                    }
                                >
                                    {props.node.name}
                                </A>
                            )}
                        </Show>
                        <Show when={hasChildren()}>
                            <span class="badge badge-sm">
                                {props.node.children.length}
                            </span>
                        </Show>
                        <Show when={isCyclic()}>
                            <span
                                class="badge badge-warning"
                                style={{ "font-size": "0.65rem" }}
                            >
                                circular
                            </span>
                        </Show>
                    </span>
                </td>
                <td class="mono" style={{ "font-size": "0.85rem" }}>
                    {props.node.version ?? <span class="text-muted">—</span>}
                </td>
                <td>
                    <Show when={props.node.type}>
                        <span class="badge badge-sm">{props.node.type}</span>
                    </Show>
                </td>
                <td class="truncate">
                    <Show
                        when={props.node.purl}
                        keyed
                        fallback={<span class="text-muted">—</span>}
                    >
                        {(purl) => <PurlLink purl={purl} showBadge />}
                    </Show>
                </td>
            </tr>
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
