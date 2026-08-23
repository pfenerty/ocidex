import { createSignal, createMemo, Show } from "solid-js";
import { A } from "@solidjs/router";
import { Button } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
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

    // A row is only expandable when it has children it is not already inside:
    // a cyclic row's children are its own ancestors, so opening it would loop.
    const expandable = (row: DepRow) => row.node.children.length > 0 && !row.isCyclic;

    const columns = (): Column<DepRow>[] => [
        {
            header: "Name",
            render: (row) => (
                <span class="tree-name" style={{ "--depth": row.depth }}>
                    <span
                        class="tree-twisty"
                        classList={{ open: expandable(row) && expandedRefs().has(row.node.ref) }}
                    >
                        {expandable(row) ? "▸" : ""}
                    </span>
                    <Show
                        when={row.node.id}
                        keyed
                        fallback={<span class="font-mono text-muted text-sm">{row.node.name}</span>}
                    >
                        {(_id) => (
                            <A
                                href={componentHref(row.node.name, row.node.group, row.node.version)}
                                class="font-mono text-sm"
                                onClick={(e: MouseEvent) => e.stopPropagation()}
                            >
                                {row.node.name}
                            </A>
                        )}
                    </Show>
                    <Show when={row.node.children.length > 0}>
                        <span class="badge badge-sm">{row.node.children.length}</span>
                    </Show>
                    <Show when={row.isCyclic}>
                        <span class="badge badge-warning badge-sm">circular</span>
                    </Show>
                </span>
            ),
        },
        {
            header: "Version",
            render: (row) => <VersionCell version={row.node.version} />,
        },
        {
            header: "Type",
            render: (row) => (
                <Show when={row.node.type} keyed>
                    {(type) => <TypeBadge type={type} />}
                </Show>
            ),
        },
        {
            header: "Package URL",
            class: "truncate",
            render: (row) => (
                <Show when={row.node.purl} keyed fallback={<span class="text-muted">—</span>}>
                    {(purl) => <PurlLink purl={purl} showBadge />}
                </Show>
            ),
        },
        {
            header: "Vulns",
            render: (row) => (
                <VulnCountBadges
                    criticalCount={row.node.criticalCount}
                    highCount={row.node.highCount}
                    mediumCount={row.node.mediumCount}
                    lowCount={row.node.lowCount}
                    unknownCount={row.node.unknownCount}
                />
            ),
        },
    ];

    return (
        <>
            <div style={{ display: "flex", gap: "0.5rem", padding: "0.5rem 0" }}>
                <Button size="sm" onClick={expandAll}>Expand all</Button>
                <Button size="sm" onClick={collapseAll}>Collapse all</Button>
            </div>
            <DataTable
                bare
                columns={columns()}
                rows={visibleRows()}
                loading={false}
                isError={false}
                emptyTitle="No dependencies"
                emptyMessage="This SBOM records no dependency relationships."
                rowClickable={expandable}
                onRowClick={(row) => toggleExpanded(row.node.ref)}
            />
        </>
    );
}
