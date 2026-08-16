import type { DiffTree } from "~/api/client";
import { parsePurl } from "~/utils/purl";

export interface TreeNode {
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

export interface Row {
    node: TreeNode;
    depth: number;
    relevantChildCount: number;
}

type Change = NonNullable<DiffTree["changes"]>[number];

export interface TreeModel {
    roots: string[];
    nodes: Map<string, TreeNode>;
    orphanChanges: Change[];
    changes: Change[];
}

export function purlBase(purl: string): string {
    const atIdx = purl.indexOf("@");
    return atIdx > 0 ? purl.slice(0, atIdx) : purl.split("?")[0];
}

// changeBadgeClass maps a change direction to its badge class. Shared by the
// tree rows and the orphan rows so the two can't disagree about a direction's
// colour.
export function changeBadgeClass(kind: string | undefined): string {
    if (kind === "added" || kind === "upgraded") return "badge badge-primary";
    if (kind === "removed" || kind === "downgraded") return "badge badge-warning";
    return "badge";
}

/**
 * buildTreeModel turns the server's DiffTree into the adjacency + change-joined
 * node map the view renders. It is pure so the ADR-0021 contract (roots come
 * from the backend, file-typed nodes are dropped, unreachable changes surface
 * as orphans) can be tested without mounting a component.
 */
export function buildTreeModel(tree: DiffTree): TreeModel {
    // Filter to non-file changes once; we use this set for the orphan list and for
    // joining changes onto nodes via change.nodeRef (set by the backend per ADR-0021 §B3).
    const filteredChanges = (tree.changes ?? []).filter(
        (c) => c.purl !== undefined && parsePurl(c.purl)?.type !== "file",
    );
    const changeByNodeRef = new Map<string, Change>();
    for (const c of filteredChanges) {
        if (c.nodeRef !== undefined && c.nodeRef !== "") changeByNodeRef.set(c.nodeRef, c);
    }

    // Build adjacency from edges. Membership in the tree comes from tree.nodes
    // (server-authoritative per ADR-0021), not the edge set — disconnected roots
    // (zero in-edges, zero out-edges) must still render.
    const adj = new Map<string, string[]>();
    for (const edge of tree.edges ?? []) {
        if (!adj.has(edge.from)) adj.set(edge.from, []);
        adj.get(edge.from)?.push(edge.to);
    }

    // Build the TreeNode map keyed on bomRef directly from tree.nodes.
    const nodes = new Map<string, TreeNode>();
    const inGraphPurls = new Set<string>();
    const inGraphIDs = new Set<string>();
    for (const node of tree.nodes ?? []) {
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
        inGraphIDs.add(node.id);
    }

    // Use backend-computed roots (anchored on metadata.component.bom-ref per ADR-0021 §B5).
    const rootRefs = tree.roots ?? [];

    // Changes with no node in the graph — surfaced separately so the user doesn't
    // lose them, since by definition they have no tree position. Removals are the
    // common case, but any direction can land here (a nodeRef pointing at a
    // file-typed node we skipped, an edge the backend couldn't resolve), and a
    // change counted in the header must always be reachable somewhere.
    const orphanChanges = filteredChanges.filter((c) => {
        if (c.nodeRef !== undefined && c.nodeRef !== "" && inGraphIDs.has(c.nodeRef)) return false;
        if (c.purl !== undefined && (inGraphPurls.has(c.purl) || inGraphPurls.has(purlBase(c.purl)))) return false;
        return true;
    });

    return { roots: rootRefs, nodes, orphanChanges, changes: filteredChanges };
}

/**
 * flattenVisibleRows walks the roots depth-first and returns the rows to render
 * in traversal order. `pathSet` tracks ancestors on the current path for cycle
 * detection — a node is cyclic only if it appears in its own ancestry, not
 * merely because it was seen before under a different parent.
 */
export function flattenVisibleRows(
    model: TreeModel,
    opts: { expanded: Set<string>; showContext: boolean; showTransitive: boolean },
): Row[] {
    const { roots, nodes } = model;
    const result: Row[] = [];
    const pathSet = new Set<string>();

    function visit(ref: string, depth: number, inChangedDirectSubtree: boolean) {
        if (pathSet.has(ref)) return;
        const node = nodes.get(ref);
        if (!node) return;
        if (node.changeKind === undefined && node.purl === undefined) return;
        if (!opts.showContext && node.changeKind === undefined && !node.hasChangedDesc) return;
        if (!opts.showTransitive && !node.isDirect && !inChangedDirectSubtree && node.changeKind === undefined) return;

        const relevantChildren = node.children.filter((childRef) => {
            const child = nodes.get(childRef);
            return child !== undefined && (child.changeKind !== undefined || child.hasChangedDesc);
        });

        result.push({ node, depth, relevantChildCount: relevantChildren.length });

        if (opts.expanded.has(ref)) {
            pathSet.add(ref);
            const childInChangedDirect = inChangedDirectSubtree || (node.isDirect && node.changeKind !== undefined);
            for (const childRef of relevantChildren) visit(childRef, depth + 1, childInChangedDirect);
            pathSet.delete(ref);
        }
    }

    for (const rootRef of roots) visit(rootRef, 0, false);
    return result;
}
