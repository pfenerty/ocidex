import { createSignal, createMemo, Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { TypeBadge, VulnCountBadges, VersionCell, PurlLink } from "~/components/cells";
import { parsePurl } from "~/utils/purl";
import { componentHref } from "./componentHref";

/* ------------------------------------------------------------------ */
/*  Dependency Tree View – flat DFS, no per-node signals              */
/* ------------------------------------------------------------------ */

interface TreeNode {
    ref: string;
    name: string;
    group?: string;
    version?: string;
    type?: string;
    id?: string;
    purl?: string;
    vulnCount?: number;
    maxSeverity?: string;
    criticalCount?: number;
    highCount?: number;
    mediumCount?: number;
    lowCount?: number;
    unknownCount?: number;
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
            {
                name: string;
                group?: string;
                version?: string;
                type?: string;
                id?: string;
                purl?: string;
                vulnCount?: number;
                maxSeverity?: string;
                criticalCount?: number;
                highCount?: number;
                mediumCount?: number;
                lowCount?: number;
                unknownCount?: number;
            }
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
            const info = {
                name,
                group: node.group,
                version,
                type,
                id: node.id,
                purl: node.purl,
                vulnCount: node.vulnCount,
                maxSeverity: node.maxSeverity,
                criticalCount: node.criticalCount,
                highCount: node.highCount,
                mediumCount: node.mediumCount,
                lowCount: node.lowCount,
                unknownCount: node.unknownCount,
            };
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
                group: info?.group,
                version: info?.version,
                type: info?.type,
                id: info?.id,
                purl: info?.purl,
                vulnCount: info?.vulnCount,
                maxSeverity: info?.maxSeverity,
                criticalCount: info?.criticalCount,
                highCount: info?.highCount,
                mediumCount: info?.mediumCount,
                lowCount: info?.lowCount,
                unknownCount: info?.unknownCount,
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
                                                    {(_id) => (
                                                        <A
                                                            href={componentHref(row.node.name, row.node.group, row.node.version)}
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
                                        <td>
                                            <VersionCell version={row.node.version} />
                                        </td>
                                        <td>
                                            <Show when={row.node.type} keyed>
                                                {(type) => <TypeBadge type={type} />}
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
                                            <VulnCountBadges
                                                criticalCount={row.node.criticalCount}
                                                highCount={row.node.highCount}
                                                mediumCount={row.node.mediumCount}
                                                lowCount={row.node.lowCount}
                                                unknownCount={row.node.unknownCount}
                                            />
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
