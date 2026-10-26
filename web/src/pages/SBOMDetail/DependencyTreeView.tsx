import { createSignal, createMemo, createEffect, on, Show } from "solid-js";
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
    /** Expanded at an earlier row; its subtree is drawn there, not again here. */
    shownAbove: boolean;
}

/** Total findings on a node; undefined counts read as zero. */
function vulnTotal(node: Pick<TreeNode, "criticalCount" | "highCount" | "mediumCount" | "lowCount" | "unknownCount">): number {
    return (
        (node.criticalCount ?? 0) +
        (node.highCount ?? 0) +
        (node.mediumCount ?? 0) +
        (node.lowCount ?? 0) +
        (node.unknownCount ?? 0)
    );
}

// The tree walks below are plain functions of the graph rather than closures inside the
// component's memos: a nested walker that closes over a memo's locals reads to
// eslint-plugin-solid's reactivity rule as a stale capture (ocidex-35uu), and pure
// functions are easier to follow anyway.

// Every walk here is linear in nodes and edges. They used to walk every path
// from the roots, and a dependency DAG shares packages: one Wolfi image's 8,516
// components had ~3.4e33 root-to-node paths, so opening its Packages tab froze
// the tab (ocidex-231j).

/** Every ref reachable from the roots. */
function reachableRefs(roots: string[], nodes: Map<string, TreeNode>): Set<string> {
    const seen = new Set<string>();
    const queue = roots.filter((r) => nodes.has(r));
    for (const r of queue) seen.add(r);
    // for...of visits items pushed during the loop, so the array is the queue.
    for (const ref of queue) {
        for (const child of nodes.get(ref)?.children ?? []) {
            if (!seen.has(child) && nodes.has(child)) {
                seen.add(child);
                queue.push(child);
            }
        }
    }
    return seen;
}

/**
 * Refs that are vulnerable or have a vulnerable descendant — every ref worth
 * drawing under the filter. Found by walking up from each vulnerable package
 * to its ancestors, so each ref is settled once however many paths reach it,
 * and a cycle cannot loop.
 */
function vulnerablePathRefs(roots: string[], nodes: Map<string, TreeNode>): Set<string> {
    const reachable = reachableRefs(roots, nodes);
    const parents = new Map<string, string[]>();
    for (const ref of reachable) {
        for (const child of nodes.get(ref)?.children ?? []) {
            if (!reachable.has(child)) continue;
            const list = parents.get(child);
            if (list === undefined) parents.set(child, [ref]);
            else list.push(ref);
        }
    }
    const keep = new Set<string>();
    const queue: string[] = [];
    for (const ref of reachable) {
        const node = nodes.get(ref);
        if (node !== undefined && vulnTotal(node) > 0) {
            keep.add(ref);
            queue.push(ref);
        }
    }
    for (const ref of queue) {
        for (const parent of parents.get(ref) ?? []) {
            if (!keep.has(parent)) {
                keep.add(parent);
                queue.push(parent);
            }
        }
    }
    return keep;
}

/** Every ref with children, reachable from the roots. */
function expandableRefs(roots: string[], nodes: Map<string, TreeNode>): Set<string> {
    const toExpand = new Set<string>();
    for (const ref of reachableRefs(roots, nodes)) {
        if ((nodes.get(ref)?.children.length ?? 0) > 0) toExpand.add(ref);
    }
    return toExpand;
}

/**
 * DFS over roots → flat array of visible rows. pathSet tracks the current
 * ancestry for cycle detection — a node is cyclic only if it appears among its
 * own ancestors. With `keep`, refs outside it are not drawn.
 *
 * A package depended on from several places is expanded at its first
 * occurrence only; later occurrences are marked shownAbove and not descended
 * into, the way `npm ls` marks a subtree "deduped". Without that, a fully
 * expanded shared DAG draws one row per path, which is unbounded in practice.
 */
function flattenVisible(
    roots: string[],
    nodes: Map<string, TreeNode>,
    expanded: Set<string>,
    keep: Set<string> | undefined,
): DepRow[] {
    const result: DepRow[] = [];
    const pathSet = new Set<string>();
    const expandedOnce = new Set<string>();
    const visit = (ref: string, depth: number) => {
        if (keep !== undefined && !keep.has(ref)) return;
        const node = nodes.get(ref);
        if (!node) return;
        const isCyclic = pathSet.has(ref);
        const opens = expanded.has(ref) && !isCyclic && node.children.length > 0;
        const shownAbove = opens && expandedOnce.has(ref);
        result.push({ node, depth, isCyclic, shownAbove });
        if (opens && !shownAbove) {
            expandedOnce.add(ref);
            pathSet.add(ref);
            for (const childRef of node.children) visit(childRef, depth + 1);
            pathSet.delete(ref);
        }
    };
    for (const rootRef of roots) visit(rootRef, 0);
    return result;
}

export function DependencyTreeView(props: {
    graph: { edges: DependencyEdge[]; nodes: ComponentSummary[]; roots?: string[] | null };
    /**
     * Show only the paths that reach a vulnerable package. This narrows the
     * tree without flattening it: the ancestry is what says which direct
     * dependency pulled the vulnerable one in, so the branches that lead
     * nowhere are dropped and the surviving depth is kept.
     */
    vulnerableOnly?: boolean;
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

    // Computed once per graph rather than per row; linear, so computing it
    // eagerly with the filter off costs nothing (see vulnerablePathRefs).
    const pathRefs = createMemo(() => {
        const { roots, nodes } = treeData();
        return vulnerablePathRefs(roots, nodes);
    });

    const [expandedRefs, setExpandedRefs] = createSignal(new Set<string>(), { equals: false });

    // Turning the filter on opens the surviving paths, so the vulnerable
    // package is on screen without a single click — the whole point of the
    // filter, given the default tree shows 8 roots over 287 packages. It seeds
    // the same signal the twisties use, so expanding and collapsing afterwards
    // behaves exactly as it does with the filter off.
    // Not deferred: a view that mounts with the filter already on has to open
    // its paths too, or the filter silently does half its job on first paint.
    createEffect(on(
        () => props.vulnerableOnly === true,
        (enabled) => {
            if (enabled) setExpandedRefs(() => new Set(pathRefs()));
        },
    ));

    const toggleExpanded = (ref: string) => {
        setExpandedRefs(s => {
            const next = new Set(s);
            if (next.has(ref)) next.delete(ref); else next.add(ref);
            return next;
        });
    };

    const expandAll = () => {
        const { roots, nodes } = treeData();
        setExpandedRefs(() => expandableRefs(roots, nodes));
    };

    const collapseAll = () => setExpandedRefs(() => new Set<string>());

    const visibleRows = createMemo((): DepRow[] => {
        const { roots, nodes } = treeData();
        const keep = props.vulnerableOnly === true ? pathRefs() : undefined;
        return flattenVisible(roots, nodes, expandedRefs(), keep);
    });

    // Children that will actually be drawn. Under the filter this is a subset,
    // and it has to be the subset the twisty and the child-count badge quote —
    // otherwise a branch whose children were all filtered away still offers an
    // arrow that opens onto nothing, and says "12" while showing one.
    const shownChildren = (node: TreeNode) => {
        const keep = props.vulnerableOnly === true ? pathRefs() : undefined;
        return keep === undefined ? node.children : node.children.filter((c) => keep.has(c));
    };

    // A row is only expandable when it has children it is not already inside:
    // a cyclic row's children are its own ancestors, so opening it would loop.
    // A shownAbove row's subtree is already on screen at its first occurrence.
    const expandable = (row: DepRow) =>
        shownChildren(row.node).length > 0 && !row.isCyclic && !row.shownAbove;

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
                    <Show when={shownChildren(row.node).length > 0}>
                        <span class="badge badge-sm">{shownChildren(row.node).length}</span>
                    </Show>
                    <Show when={row.isCyclic}>
                        <span class="badge badge-warning badge-sm">circular</span>
                    </Show>
                    <Show when={row.shownAbove}>
                        <span class="text-muted text-sm" title="This package's dependencies are listed where it first appears above">
                            shown above
                        </span>
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
            <div class="flex gap-2 py-2">
                <Button size="sm" onClick={expandAll}>Expand all</Button>
                <Button size="sm" onClick={collapseAll}>Collapse all</Button>
            </div>
            <DataTable
                bare
                // Same reason as the diff tree: stacked rows lose the depth
                // that says which package pulled in which.
                mobileLayout="scroll"
                columns={columns()}
                rows={visibleRows()}
                loading={false}
                isError={false}
                emptyTitle={props.vulnerableOnly === true ? "No vulnerable dependencies" : "No dependencies"}
                emptyMessage={
                    props.vulnerableOnly === true
                        ? "No package in this dependency graph has a recorded vulnerability."
                        : "This SBOM records no dependency relationships."
                }
                rowClickable={expandable}
                onRowClick={(row) => toggleExpanded(row.node.ref)}
            />
        </>
    );
}
