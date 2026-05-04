import { createMemo, createSignal, Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { relativeDate } from "~/utils/format";
import { classifyChange, changelogRefLabel } from "~/utils/diff";
import type { DiffTree } from "~/api/client";
import { parsePurl } from "~/utils/purl";

interface TreeNode {
    ref: string;
    name: string;
    version?: string;
    previousVersion?: string;
    purl?: string;
    id?: string;
    changeKind?: ReturnType<typeof classifyChange>;
    children: string[];
    hasChangedDesc: boolean;
}

function purlBase(purl: string): string {
    const atIdx = purl.indexOf("@");
    return atIdx > 0 ? purl.slice(0, atIdx) : purl.split("?")[0];
}

export function DiffTreeView(props: { tree: DiffTree }) {
    const treeData = createMemo(() => {
        // Build nameMap from non-file nodes
        const nameMap = new Map<
            string,
            { name: string; version?: string; id?: string; purl?: string }
        >();
        for (const node of props.tree.nodes ?? []) {
            const type = parsePurl(node.purl ?? "")?.type ?? node.type;
            if (type === "file") continue;
            const name =
                node.group !== undefined && node.group !== ""
                    ? `${node.group}/${node.name}`
                    : node.name;
            const version =
                node.version !== undefined && node.version !== ""
                    ? node.version
                    : undefined;
            const info = { name, version, id: node.id, purl: node.purl !== "" ? node.purl : undefined };
            nameMap.set(node.id, info);
            nameMap.set(node.name, info);
            if (node.purl !== undefined && node.purl !== "") {
                nameMap.set(node.purl, info);
                nameMap.set(purlBase(node.purl), info);
            }
            if (node.bomRef !== undefined && node.bomRef !== "") nameMap.set(node.bomRef, info);
        }

        // Build change lookup from package-only changes
        interface ChangeInfo {
            kind: ReturnType<typeof classifyChange>;
            version?: string;
            previousVersion?: string;
        }
        const changeMap = new Map<string, ChangeInfo>();
        const filteredChanges = (props.tree.changes ?? []).filter(
            (c) => c.purl !== undefined && parsePurl(c.purl)?.type !== "file",
        );
        for (const c of filteredChanges) {
            const info: ChangeInfo = {
                kind: classifyChange(c),
                version: c.version,
                previousVersion: c.previousVersion,
            };
            if (c.purl !== undefined && c.purl !== "") {
                changeMap.set(c.purl, info);
                changeMap.set(purlBase(c.purl), info);
            }
            const nameKey =
                c.group !== undefined && c.group !== ""
                    ? `${c.group}/${c.name}`
                    : c.name;
            if (!changeMap.has(nameKey)) changeMap.set(nameKey, info);
        }

        // Build adjacency
        const adj = new Map<string, string[]>();
        const allTargets = new Set<string>();
        for (const edge of props.tree.edges ?? []) {
            if (!nameMap.has(edge.from) || !nameMap.has(edge.to)) continue;
            if (!adj.has(edge.from)) adj.set(edge.from, []);
            adj.get(edge.from)?.push(edge.to);
            allTargets.add(edge.to);
        }

        // Build annotated tree nodes
        const allRefs = new Set([...adj.keys(), ...allTargets]);
        const nodes = new Map<string, TreeNode>();
        for (const ref of allRefs) {
            const info = nameMap.get(ref);
            if (!info) continue;
            const changeInfo =
                (info.purl !== undefined ? changeMap.get(info.purl) : undefined) ??
                (info.purl !== undefined ? changeMap.get(purlBase(info.purl)) : undefined) ??
                changeMap.get(info.name);
            nodes.set(ref, {
                ref,
                name: info.name,
                version: changeInfo?.version ?? info.version,
                previousVersion: changeInfo?.previousVersion,
                purl: info.purl,
                id: info.id,
                changeKind: changeInfo?.kind,
                children: adj.get(ref) ?? [],
                hasChangedDesc: false,
            });
        }

        // Find roots
        const fromRefs = [...adj.keys()];
        let rootRefs = fromRefs.filter((r) => !allTargets.has(r));
        if (rootRefs.length === 0) rootRefs = fromRefs.slice(0, 10);

        // DFS to mark nodes with changed descendants
        const mark = (ref: string, visited: Set<string>): boolean => {
            if (visited.has(ref)) return false;
            visited.add(ref);
            const node = nodes.get(ref);
            if (!node) return false;
            let childChanged = false;
            for (const childRef of node.children) {
                if (mark(childRef, visited)) childChanged = true;
            }
            node.hasChangedDesc = childChanged;
            return node.changeKind !== undefined || childChanged;
        };
        const markVisited = new Set<string>();
        for (const r of rootRefs) mark(r, markVisited);

        // Filter roots to those with changes or changed descendants
        const relevantRoots = rootRefs.filter((r) => {
            const n = nodes.get(r);
            return n !== undefined && (n.changeKind !== undefined || n.hasChangedDesc);
        });

        // Removed packages not present in the new graph
        const inGraphPurls = new Set<string>();
        for (const n of nodes.values()) {
            if (n.purl !== undefined) {
                inGraphPurls.add(n.purl);
                inGraphPurls.add(purlBase(n.purl));
            }
        }
        const removedOrphans = filteredChanges.filter((c) => {
            if (classifyChange(c) !== "removed") return false;
            return (
                (c.purl === undefined || (!inGraphPurls.has(c.purl) && !inGraphPurls.has(purlBase(c.purl)))) &&
                !nodes.has(c.name)
            );
        });

        return {
            roots: relevantRoots.length > 0 ? relevantRoots : rootRefs,
            nodes,
            removedOrphans,
        };
    });

    // Summary counts for the header badges.
    const changes = () => (props.tree.changes ?? []).filter(
        (c) => c.purl !== undefined && parsePurl(c.purl)?.type !== "file",
    );
    const addedCount   = () => changes().filter((c) => c.type === "added").length;
    const removedCount = () => changes().filter((c) => c.type === "removed").length;
    const upgradedCount   = () => changes().filter((c) => classifyChange(c) === "upgraded").length;
    const downgradedCount = () => changes().filter((c) => classifyChange(c) === "downgraded").length;

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
                    <A href={`/sboms/${props.tree.from.id}`} class="mono">
                        {changelogRefLabel(props.tree.from)}
                    </A>
                    {" → "}
                    <A href={`/sboms/${props.tree.to.id}`} class="mono">
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
                        <For each={treeData().roots}>
                            {(rootRef) => {
                                const node = treeData().nodes.get(rootRef);
                                return node !== undefined ? (
                                    <DiffTreeNodeRow
                                        node={node}
                                        allNodes={treeData().nodes}
                                        depth={0}
                                        visited={new Set()}
                                    />
                                ) : null;
                            }}
                        </For>
                        <Show when={treeData().removedOrphans.length > 0}>
                            <For each={treeData().removedOrphans}>
                                {(c) => (
                                    <tr>
                                        <td>
                                            <span
                                                class="mono"
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
                                        <td class="mono" style={{ "font-size": "0.85rem" }}>
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
        </div>
    );
}

function DiffTreeNodeRow(props: {
    node: TreeNode;
    allNodes: Map<string, TreeNode>;
    depth: number;
    visited: Set<string>;
}) {
    const isCyclic = () => props.visited.has(props.node.ref);
    const isChanged = () => props.node.changeKind !== undefined;

    // Hide context (ancestor) nodes that have no purl — structural/env entries.
    const isVisible = () => isChanged() || props.node.purl !== undefined;

    const relevantChildren = () =>
        props.node.children.filter((ref) => {
            const child = props.allNodes.get(ref);
            return child !== undefined && (child.changeKind !== undefined || child.hasChangedDesc);
        });

    const [expanded, setExpanded] = createSignal(false);

    const childNodes = createMemo(() => {
        if (!expanded() || isCyclic()) return [];
        return relevantChildren()
            .map((ref) => props.allNodes.get(ref))
            .filter((n): n is TreeNode => n !== undefined);
    });

    const nextVisited = createMemo(() => {
        const s = new Set(props.visited);
        s.add(props.node.ref);
        return s;
    });

    const changeCls = () => {
        const k = props.node.changeKind;
        if (k === "added" || k === "upgraded") return "badge-primary";   // blue
        if (k === "removed" || k === "downgraded") return "badge-warning"; // amber
        return "";  // neutral for modified
    };

    return (
        <Show when={!isCyclic() && isVisible()}>
            <>
                <tr
                    style={{
                        cursor: relevantChildren().length > 0 ? "pointer" : "default",
                        opacity: isChanged() ? "1" : "0.55",
                    }}
                    onClick={() =>
                        relevantChildren().length > 0 && setExpanded(!expanded())
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
                                        relevantChildren().length > 0 && expanded()
                                            ? "rotate(90deg)"
                                            : "rotate(0deg)",
                                }}
                            >
                                {relevantChildren().length > 0 ? "▸" : ""}
                            </span>
                            <Show
                                when={props.node.id}
                                keyed
                                fallback={
                                    <span
                                        class="mono"
                                        style={{ "font-size": "0.85rem" }}
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
                            <Show when={!isChanged() && relevantChildren().length > 0}>
                                <span class="badge badge-sm">
                                    {relevantChildren().length}
                                </span>
                            </Show>
                        </span>
                    </td>
                    <td>
                        <Show when={isChanged()}>
                            <span class={`badge ${changeCls()}`}>
                                {props.node.changeKind}
                            </span>
                        </Show>
                    </td>
                    <td class="mono" style={{ "font-size": "0.85rem" }}>
                        <Show when={props.node.previousVersion}>
                            <span class="text-muted">{props.node.previousVersion}</span>
                            {" → "}
                        </Show>
                        {props.node.version ?? (
                            <span class="text-muted">—</span>
                        )}
                    </td>
                </tr>
                <Show when={expanded() && !isCyclic()}>
                    <For each={childNodes()}>
                        {(child) => (
                            <DiffTreeNodeRow
                                node={child}
                                allNodes={props.allNodes}
                                depth={props.depth + 1}
                                visited={nextVisited()}
                            />
                        )}
                    </For>
                </Show>
            </>
        </Show>
    );
}
