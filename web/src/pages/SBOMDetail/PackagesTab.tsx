import "~/components/Pagination.css";
import { createSignal, createMemo, Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import LoadMore from "~/components/LoadMore";
import PurlLink from "~/components/PurlLink";
import { VulnBadge } from "~/components/VulnBadge";
import { plural } from "~/utils/format";
import { parsePurl } from "~/utils/purl";

/* ------------------------------------------------------------------ */
/*  Packages Tab                                                       */
/* ------------------------------------------------------------------ */

export function PackagesTab(props: {
    components: ComponentSummary[];
    depsGraph?: { edges: DependencyEdge[]; nodes: ComponentSummary[] };
    // Keyset load-more over the (server-paginated) component list. The text and
    // type filters apply only to already-loaded packages.
    hasMore?: boolean;
    loadingMore?: boolean;
    onLoadMore?: () => void;
}) {
    const [filter, setFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("all");
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");

    const ecoType = (c: ComponentSummary) =>
        parsePurl(c.purl ?? "")?.type ?? c.type;

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

    const updateFilter = (v: string) => setFilter(v);
    const updateType = (v: string) => setTypeFilter(v);

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
                <div class="search-bar mb-4" style={{ "flex-wrap": "wrap" }}>
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
                                            <th>Vulns</th>
                                            <th>Package URL</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <For each={filtered()}>
                                            {(c) => (
                                                <tr>
                                                    <td>
                                                        <A href={`/components/${c.id}`}>
                                                            {c.group !== undefined && c.group !== "" ? `${c.group}/` : ""}
                                                            {c.name}
                                                        </A>
                                                    </td>
                                                    <td class="font-mono text-sm">
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
                                                    <td>
                                                        <VulnBadge count={c.vulnCount} maxSeverity={c.maxSeverity} />
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

                            <LoadMore
                                hasMore={props.hasMore ?? false}
                                loading={props.loadingMore ?? false}
                                onClick={() => props.onLoadMore?.()}
                            />
                        </>
                    }
                >
                    {(graph) => <DependencyTreeView graph={graph} />}
                </Show>
            </div>
        </Show>
    );
}

/* ------------------------------------------------------------------ */
/*  Dependency Tree View – flat DFS, no per-node signals              */
/* ------------------------------------------------------------------ */

interface TreeNode {
    ref: string;
    name: string;
    version?: string;
    type?: string;
    id?: string;
    purl?: string;
    vulnCount?: number;
    maxSeverity?: string;
    children: string[];
}

interface DepRow {
    node: TreeNode;
    depth: number;
    isCyclic: boolean;
}

export function DependencyTreeView(props: {
    graph: { edges: DependencyEdge[]; nodes: ComponentSummary[]; roots?: string[] | null };
}) {
    const treeData = createMemo(() => {
        const nameMap = new Map<
            string,
            { name: string; version?: string; type?: string; id?: string; purl?: string; vulnCount?: number; maxSeverity?: string }
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
            const info = { name, version, type, id: node.id, purl: node.purl, vulnCount: node.vulnCount, maxSeverity: node.maxSeverity };
            nameMap.set(node.id, info);
            nameMap.set(node.name, info);
            if (node.purl !== undefined) nameMap.set(node.purl, info);
            if (node.bomRef !== undefined) nameMap.set(node.bomRef, info);
        }

        const edges = props.graph.edges.filter(
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

        const rootRefs = props.graph.roots ?? [];

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
                vulnCount: info?.vulnCount,
                maxSeverity: info?.maxSeverity,
                children: adj.get(ref) ?? [],
            });
        }

        return { roots: rootRefs, nodes };
    });

    const [expandedRefs, setExpandedRefs] = createSignal(new Set<string>(), { equals: false });

    const toggleExpanded = (ref: string) => {
        setExpandedRefs(s => {
            const next = new Set(s);
            if (next.has(ref)) next.delete(ref); else next.add(ref);
            return next;
        });
    };

    const expandAll = () => {
        const { roots, nodes } = treeData();
        const toExpand = new Set<string>();
        const pathSet = new Set<string>();
        function collect(ref: string) {
            if (pathSet.has(ref)) return;
            const node = nodes.get(ref);
            if (!node) return;
            if (node.children.length > 0) toExpand.add(ref);
            pathSet.add(ref);
            for (const childRef of node.children) collect(childRef);
            pathSet.delete(ref);
        }
        for (const rootRef of roots) collect(rootRef);
        setExpandedRefs(() => toExpand);
    };

    const collapseAll = () => setExpandedRefs(() => new Set<string>());

    // DFS over roots → flat array of visible rows. pathSet tracks the current ancestry
    // path for cycle detection — a node is cyclic only if it appears among its own ancestors.
    const visibleRows = createMemo((): DepRow[] => {
        const { roots, nodes } = treeData();
        const expanded = expandedRefs();
        const result: DepRow[] = [];
        const pathSet = new Set<string>();

        function visit(ref: string, depth: number) {
            const node = nodes.get(ref);
            if (!node) return;
            const isCyclic = pathSet.has(ref);
            result.push({ node, depth, isCyclic });
            if (expanded.has(ref) && !isCyclic) {
                pathSet.add(ref);
                for (const childRef of node.children) visit(childRef, depth + 1);
                pathSet.delete(ref);
            }
        }

        for (const rootRef of roots) visit(rootRef, 0);
        return result;
    });

    return (
        <>
            <div style={{ display: "flex", gap: "0.5rem", padding: "0.5rem 0" }}>
                <button class="btn btn-sm" onClick={expandAll}>Expand all</button>
                <button class="btn btn-sm" onClick={collapseAll}>Collapse all</button>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Version</th>
                            <th>Type</th>
                            <th>Package URL</th>
                            <th>Vulns</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={visibleRows()}>
                            {(row) => {
                                const isExpanded = () => expandedRefs().has(row.node.ref);
                                const hasChildren = row.node.children.length > 0;
                                return (
                                    <tr
                                        style={{
                                            cursor: hasChildren && !row.isCyclic ? "pointer" : "default",
                                        }}
                                        onClick={() => hasChildren && !row.isCyclic && toggleExpanded(row.node.ref)}
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
                                                        transform: hasChildren && !row.isCyclic && isExpanded()
                                                            ? "rotate(90deg)"
                                                            : "rotate(0deg)",
                                                    }}
                                                >
                                                    {hasChildren && !row.isCyclic ? "▸" : ""}
                                                </span>
                                                <Show
                                                    when={row.node.id}
                                                    keyed
                                                    fallback={
                                                        <span
                                                            class="font-mono"
                                                            style={{
                                                                "font-size": "0.85rem",
                                                                color: "var(--color-text-muted)",
                                                            }}
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
                                                            onClick={(e: MouseEvent) => e.stopPropagation()}
                                                        >
                                                            {row.node.name}
                                                        </A>
                                                    )}
                                                </Show>
                                                <Show when={hasChildren}>
                                                    <span class="badge badge-sm">{row.node.children.length}</span>
                                                </Show>
                                                <Show when={row.isCyclic}>
                                                    <span class="badge badge-warning" style={{ "font-size": "0.65rem" }}>circular</span>
                                                </Show>
                                            </span>
                                        </td>
                                        <td class="font-mono" style={{ "font-size": "0.85rem" }}>
                                            {row.node.version ?? <span class="text-muted">—</span>}
                                        </td>
                                        <td>
                                            <Show when={row.node.type}>
                                                <span class="badge badge-sm">{row.node.type}</span>
                                            </Show>
                                        </td>
                                        <td class="truncate">
                                            <Show
                                                when={row.node.purl}
                                                keyed
                                                fallback={<span class="text-muted">—</span>}
                                            >
                                                {(purl) => <PurlLink purl={purl} showBadge />}
                                            </Show>
                                        </td>
                                        <td>
                                            <VulnBadge count={row.node.vulnCount} maxSeverity={row.node.maxSeverity} />
                                        </td>
                                    </tr>
                                );
                            }}
                        </For>
                    </tbody>
                </table>
            </div>
        </>
    );
}
