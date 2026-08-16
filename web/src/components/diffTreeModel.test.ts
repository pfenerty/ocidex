import { describe, it, expect } from "vitest";
import { buildTreeModel, flattenVisibleRows, purlBase, changeBadgeClass } from "./diffTreeModel";
import type { DiffTree } from "~/api/client";

type Node = NonNullable<DiffTree["nodes"]>[number];
type Change = NonNullable<DiffTree["changes"]>[number];

function makeTree(overrides: Partial<DiffTree> = {}): DiffTree {
    return {
        from: { id: "from-id", createdAt: "2026-05-01T00:00:00Z" },
        to: { id: "to-id", createdAt: "2026-05-02T00:00:00Z" },
        summary: { added: 0, removed: 0, upgraded: 0, downgraded: 0, modified: 0 },
        changes: [],
        nodes: [],
        edges: [],
        roots: [],
        ...overrides,
    };
}

function node(o: Partial<Node> & { id: string; name: string; bomRef: string }): Node {
    return {
        sbomId: "to-id",
        type: "library",
        isDirect: false,
        ...o,
    };
}

function change(o: Partial<Change> & { name: string; type: string; direction: string }): Change {
    return { ...o };
}

const noChanges = { added: 0, removed: 0, upgraded: 0, downgraded: 0, modified: 0 };

describe("purlBase", () => {
    it("strips the version", () => {
        expect(purlBase("pkg:npm/left-pad@1.3.0")).toBe("pkg:npm/left-pad");
    });

    it("strips qualifiers when there is no version", () => {
        expect(purlBase("pkg:apk/alpine/musl?arch=x86_64")).toBe("pkg:apk/alpine/musl");
    });
});

describe("changeBadgeClass", () => {
    it("colours gains primary and losses warning", () => {
        expect(changeBadgeClass("added")).toBe("badge badge-primary");
        expect(changeBadgeClass("upgraded")).toBe("badge badge-primary");
        expect(changeBadgeClass("removed")).toBe("badge badge-warning");
        expect(changeBadgeClass("downgraded")).toBe("badge badge-warning");
        expect(changeBadgeClass(undefined)).toBe("badge");
    });
});

describe("buildTreeModel", () => {
    it("uses the backend's roots verbatim (ADR-0021 §B5)", () => {
        const model = buildTreeModel(
            makeTree({
                roots: ["ref-app"],
                nodes: [
                    node({ id: "n-app", name: "app", bomRef: "ref-app", purl: "pkg:oci/app@1.0.0" }),
                    node({ id: "n-lib", name: "lib", bomRef: "ref-lib", purl: "pkg:npm/lib@1.0.0" }),
                ],
                edges: [{ from: "ref-app", to: "ref-lib" }],
            }),
        );

        // ref-lib has zero in-edges from the caller's perspective but is *not*
        // promoted to a root — root-ness is the server's call.
        expect(model.roots).toEqual(["ref-app"]);
        expect(model.nodes.get("ref-app")?.children).toEqual(["ref-lib"]);
    });

    it("drops file-typed nodes and file-typed changes", () => {
        const model = buildTreeModel(
            makeTree({
                nodes: [
                    node({ id: "n-f", name: "/etc/hosts", bomRef: "ref-f", purl: "pkg:file/etc/hosts" }),
                    node({ id: "n-t", name: "typed-file", bomRef: "ref-t", type: "file" }),
                    node({ id: "n-lib", name: "lib", bomRef: "ref-lib", purl: "pkg:npm/lib@1.0.0" }),
                ],
                changes: [
                    change({ name: "/etc/hosts", type: "modified", direction: "upgraded", purl: "pkg:file/etc/hosts" }),
                    change({ name: "lib", type: "modified", direction: "upgraded", purl: "pkg:npm/lib@1.0.0", nodeRef: "n-lib" }),
                ],
            }),
        );

        expect([...model.nodes.keys()]).toEqual(["ref-lib"]);
        expect(model.changes.map((c) => c.name)).toEqual(["lib"]);
    });

    it("joins a change onto its node via nodeRef", () => {
        const model = buildTreeModel(
            makeTree({
                nodes: [
                    node({
                        id: "n-lib",
                        name: "lib",
                        group: "org",
                        bomRef: "ref-lib",
                        purl: "pkg:npm/org/lib@2.0.0",
                        version: "2.0.0",
                    }),
                ],
                changes: [
                    change({
                        name: "lib",
                        type: "modified",
                        direction: "upgraded",
                        purl: "pkg:npm/org/lib@2.0.0",
                        version: "2.0.0",
                        previousVersion: "1.0.0",
                        nodeRef: "n-lib",
                    }),
                ],
            }),
        );

        const n = model.nodes.get("ref-lib");
        expect(n?.name).toBe("org/lib");
        expect(n?.changeKind).toBe("upgraded");
        expect(n?.version).toBe("2.0.0");
        expect(n?.previousVersion).toBe("1.0.0");
        expect(model.orphanChanges).toHaveLength(0);
    });

    it("derives hasChangedDesc from the backend's descendantChanges", () => {
        const model = buildTreeModel(
            makeTree({
                nodes: [
                    node({
                        id: "n-a",
                        name: "a",
                        bomRef: "ref-a",
                        purl: "pkg:npm/a@1.0.0",
                        descendantChanges: { ...noChanges, upgraded: 2 },
                    }),
                    node({
                        id: "n-b",
                        name: "b",
                        bomRef: "ref-b",
                        purl: "pkg:npm/b@1.0.0",
                        descendantChanges: { ...noChanges },
                    }),
                    node({ id: "n-c", name: "c", bomRef: "ref-c", purl: "pkg:npm/c@1.0.0" }),
                ],
            }),
        );

        expect(model.nodes.get("ref-a")?.hasChangedDesc).toBe(true);
        expect(model.nodes.get("ref-b")?.hasChangedDesc).toBe(false);
        expect(model.nodes.get("ref-c")?.hasChangedDesc).toBe(false);
    });

    it("surfaces a change with no node in the graph as an orphan", () => {
        const model = buildTreeModel(
            makeTree({
                nodes: [node({ id: "n-lib", name: "lib", bomRef: "ref-lib", purl: "pkg:npm/lib@1.0.0" })],
                changes: [
                    change({
                        name: "gone",
                        type: "removed",
                        direction: "",
                        purl: "pkg:npm/gone@0.9.0",
                    }),
                ],
            }),
        );

        expect(model.orphanChanges.map((c) => c.name)).toEqual(["gone"]);
    });

    it("does not orphan a change that matches a graph node on purl base alone", () => {
        // No nodeRef, and the versions differ — the purl-base fallback is what
        // keeps an upgrade from being counted in the header and rendered twice.
        const model = buildTreeModel(
            makeTree({
                nodes: [node({ id: "n-lib", name: "lib", bomRef: "ref-lib", purl: "pkg:npm/lib@2.0.0" })],
                changes: [
                    change({ name: "lib", type: "modified", direction: "upgraded", purl: "pkg:npm/lib@1.0.0" }),
                ],
            }),
        );

        expect(model.orphanChanges).toHaveLength(0);
    });

    it("orphans a change whose nodeRef points at a node that was dropped", () => {
        const model = buildTreeModel(
            makeTree({
                nodes: [node({ id: "n-f", name: "cfg", bomRef: "ref-f", purl: "pkg:file/etc/cfg" })],
                changes: [
                    change({
                        name: "ghost",
                        type: "modified",
                        direction: "upgraded",
                        purl: "pkg:npm/ghost@1.0.0",
                        nodeRef: "n-f",
                    }),
                ],
            }),
        );

        expect(model.orphanChanges.map((c) => c.name)).toEqual(["ghost"]);
    });
});

/** A three-level tree: app → direct → transitive, with the change at the leaf. */
function nestedTree(): DiffTree {
    return makeTree({
        roots: ["ref-app"],
        nodes: [
            node({
                id: "n-app",
                name: "app",
                bomRef: "ref-app",
                purl: "pkg:oci/app@1.0.0",
                isDirect: true,
                descendantChanges: { ...noChanges, upgraded: 1 },
            }),
            node({
                id: "n-direct",
                name: "direct",
                bomRef: "ref-direct",
                purl: "pkg:npm/direct@1.0.0",
                isDirect: true,
                descendantChanges: { ...noChanges, upgraded: 1 },
            }),
            node({
                id: "n-leaf",
                name: "leaf",
                bomRef: "ref-leaf",
                purl: "pkg:npm/leaf@2.0.0",
            }),
            node({
                id: "n-quiet",
                name: "quiet",
                bomRef: "ref-quiet",
                purl: "pkg:npm/quiet@1.0.0",
                isDirect: true,
            }),
        ],
        edges: [
            { from: "ref-app", to: "ref-direct" },
            { from: "ref-app", to: "ref-quiet" },
            { from: "ref-direct", to: "ref-leaf" },
        ],
        changes: [
            change({
                name: "leaf",
                type: "modified",
                direction: "upgraded",
                purl: "pkg:npm/leaf@2.0.0",
                version: "2.0.0",
                previousVersion: "1.0.0",
                nodeRef: "n-leaf",
            }),
        ],
    });
}

const allExpanded = new Set(["ref-app", "ref-direct", "ref-quiet", "ref-leaf"]);

describe("flattenVisibleRows", () => {
    const model = buildTreeModel(nestedTree());

    it("renders children only under an expanded parent", () => {
        const collapsed = flattenVisibleRows(model, {
            expanded: new Set(),
            showContext: true,
            showTransitive: true,
        });
        expect(collapsed.map((r) => r.node.ref)).toEqual(["ref-app"]);
        // app has one relevant child (direct, which carries a changed descendant);
        // quiet is unchanged with no changed descendants and doesn't count.
        expect(collapsed[0].relevantChildCount).toBe(1);
    });

    it("walks depth-first with increasing depth when expanded", () => {
        const rows = flattenVisibleRows(model, {
            expanded: allExpanded,
            showContext: true,
            showTransitive: true,
        });
        expect(rows.map((r) => [r.node.ref, r.depth])).toEqual([
            ["ref-app", 0],
            ["ref-direct", 1],
            ["ref-leaf", 2],
        ]);
    });

    it("hides unchanged context nodes when showContext is off", () => {
        // app and direct are unchanged themselves, but both have changed
        // descendants, so they survive as the path to the leaf. quiet has
        // neither and is excluded either way.
        const rows = flattenVisibleRows(model, {
            expanded: allExpanded,
            showContext: false,
            showTransitive: true,
        });
        expect(rows.map((r) => r.node.ref)).toEqual(["ref-app", "ref-direct", "ref-leaf"]);
        expect(rows.some((r) => r.node.ref === "ref-quiet")).toBe(false);
    });

    it("keeps a quiet root only when showContext is on", () => {
        // Descent is gated on relevantChildren (change or changed descendant),
        // so a quiet subtree is unreachable regardless — showContext only ever
        // decides whether a quiet *root* is drawn.
        const tree = nestedTree();
        tree.roots = ["ref-app", "ref-quiet"];
        const m = buildTreeModel(tree);

        const off = flattenVisibleRows(m, {
            expanded: allExpanded,
            showContext: false,
            showTransitive: true,
        });
        expect(off.map((r) => r.node.ref)).not.toContain("ref-quiet");

        const on = flattenVisibleRows(m, {
            expanded: allExpanded,
            showContext: true,
            showTransitive: true,
        });
        expect(on.map((r) => r.node.ref)).toContain("ref-quiet");
    });

    it("shows a changed transitive dependency even with showTransitive off", () => {
        // The leaf is indirect, but it is itself changed — a change must never
        // be hidden by the transitive filter alone.
        const rows = flattenVisibleRows(model, {
            expanded: allExpanded,
            showContext: false,
            showTransitive: false,
        });
        expect(rows.map((r) => r.node.ref)).toContain("ref-leaf");
    });

    it("prunes a whole indirect branch when showTransitive is off", () => {
        // ref-direct demoted to indirect: it is unchanged itself, so the
        // transitive filter cuts it — and the changed leaf below it goes with
        // it, since it is never reached.
        const tree = nestedTree();
        const mid = tree.nodes?.find((n) => n.bomRef === "ref-direct");
        if (mid) mid.isDirect = false;
        const m = buildTreeModel(tree);

        const off = flattenVisibleRows(m, {
            expanded: allExpanded,
            showContext: true,
            showTransitive: false,
        });
        expect(off.map((r) => r.node.ref)).toEqual(["ref-app"]);

        const on = flattenVisibleRows(m, {
            expanded: allExpanded,
            showContext: true,
            showTransitive: true,
        });
        expect(on.map((r) => r.node.ref)).toEqual(["ref-app", "ref-direct", "ref-leaf"]);
    });

    it("terminates on a cycle without repeating a node in its own ancestry", () => {
        const tree = nestedTree();
        tree.edges?.push({ from: "ref-leaf", to: "ref-direct" });
        const m = buildTreeModel(tree);

        const rows = flattenVisibleRows(m, {
            expanded: allExpanded,
            showContext: true,
            showTransitive: true,
        });
        expect(rows.map((r) => r.node.ref)).toEqual(["ref-app", "ref-direct", "ref-leaf"]);
    });

    it("renders a diamond dependency once per parent", () => {
        // Not a cycle: shared is reachable by two disjoint paths, so it appears
        // under each. The cycle guard is ancestry-scoped, not visited-scoped.
        const tree = nestedTree();
        tree.nodes?.push(
            node({
                id: "n-shared",
                name: "shared",
                bomRef: "ref-shared",
                purl: "pkg:npm/shared@3.0.0",
            }),
        );
        tree.changes?.push(
            change({
                name: "shared",
                type: "added",
                direction: "added",
                purl: "pkg:npm/shared@3.0.0",
                version: "3.0.0",
                nodeRef: "n-shared",
            }),
        );
        tree.edges?.push({ from: "ref-app", to: "ref-shared" }, { from: "ref-direct", to: "ref-shared" });
        const m = buildTreeModel(tree);

        const rows = flattenVisibleRows(m, {
            expanded: new Set([...allExpanded, "ref-shared"]),
            showContext: true,
            showTransitive: true,
        });
        expect(rows.filter((r) => r.node.ref === "ref-shared")).toHaveLength(2);
    });

    it("skips a root the backend named but did not send a node for", () => {
        const m = buildTreeModel(makeTree({ roots: ["ref-missing"] }));
        expect(flattenVisibleRows(m, {
            expanded: new Set(),
            showContext: true,
            showTransitive: true,
        })).toEqual([]);
    });
});
