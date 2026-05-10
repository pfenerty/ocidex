// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { DiffTreeView } from "./DiffTreeView";
import type { DiffTree } from "~/api/client";

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: unknown; class?: string }) => (
        <a href={props.href} class={props.class}>{props.children as never}</a>
    ),
}));

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

function makeNode(o: {
    id: string;
    name: string;
    bomRef: string;
    purl?: string;
    isDirect?: boolean;
    descendantChanges?: { added: number; removed: number; upgraded: number; downgraded: number; modified: number };
}) {
    return {
        id: o.id,
        sbomId: "to-id",
        name: o.name,
        type: "library",
        bomRef: o.bomRef,
        purl: o.purl,
        isDirect: o.isDirect ?? false,
        descendantChanges: o.descendantChanges,
    };
}

describe("DiffTreeView", () => {
    it("renders a disconnected root (zero in-edges, zero out-edges) with its change badge", () => {
        // Reproduces the keycloak bug: keycloak-common is in roots[] with an
        // upgraded change, but has no edges. Must still render.
        const tree = makeTree({
            roots: ["pkg:maven/org.keycloak/keycloak-common@16.0.0"],
            nodes: [
                makeNode({
                    id: "node-kc-common",
                    name: "keycloak-common",
                    bomRef: "pkg:maven/org.keycloak/keycloak-common@16.0.0",
                    purl: "pkg:maven/org.keycloak/keycloak-common@16.0.0",
                }),
            ],
            edges: [],
            changes: [
                {
                    type: "modified",
                    direction: "upgraded",
                    name: "keycloak-common",
                    purl: "pkg:maven/org.keycloak/keycloak-common@16.0.0",
                    version: "16.0.0",
                    previousVersion: "15.0.0",
                    nodeRef: "node-kc-common",
                },
            ],
            summary: { added: 0, removed: 0, upgraded: 1, downgraded: 0, modified: 0 },
        });

        const { getByText } = render(() => <DiffTreeView tree={tree} />);
        expect(getByText("keycloak-common")).toBeDefined();
        expect(getByText("upgraded")).toBeDefined();
    });

    it("renders all roots, including disconnected ones, when mixed with connected ones", () => {
        const tree = makeTree({
            roots: ["A", "B", "C"],
            nodes: [
                makeNode({ id: "n-A", name: "pkg-A", bomRef: "A", purl: "pkg:maven/test/pkg-A@1.0" }),
                makeNode({ id: "n-B", name: "pkg-B", bomRef: "B", purl: "pkg:maven/test/pkg-B@1.0" }),
                makeNode({ id: "n-C", name: "pkg-C", bomRef: "C", purl: "pkg:maven/test/pkg-C@1.0" }),
                makeNode({ id: "n-X", name: "pkg-X", bomRef: "X", purl: "pkg:maven/test/pkg-X@1.0" }),
            ],
            // Only A has children; B and C have no edges at all.
            edges: [{ from: "A", to: "X" }],
            changes: [
                {
                    type: "modified",
                    direction: "upgraded",
                    name: "pkg-A",
                    purl: "pkg:maven/test/pkg-A@1.0",
                    version: "1.0",
                    previousVersion: "0.9",
                    nodeRef: "n-A",
                },
                {
                    type: "modified",
                    direction: "upgraded",
                    name: "pkg-B",
                    purl: "pkg:maven/test/pkg-B@1.0",
                    version: "1.0",
                    previousVersion: "0.9",
                    nodeRef: "n-B",
                },
                {
                    type: "modified",
                    direction: "upgraded",
                    name: "pkg-C",
                    purl: "pkg:maven/test/pkg-C@1.0",
                    version: "1.0",
                    previousVersion: "0.9",
                    nodeRef: "n-C",
                },
            ],
            summary: { added: 0, removed: 0, upgraded: 3, downgraded: 0, modified: 0 },
        });

        const { getByText } = render(() => <DiffTreeView tree={tree} />);
        expect(getByText("pkg-A")).toBeDefined();
        expect(getByText("pkg-B")).toBeDefined();
        expect(getByText("pkg-C")).toBeDefined();
    });

    it("shows fallback message when both roots and orphans are empty", () => {
        const tree = makeTree({ roots: [], nodes: [], edges: [], changes: [] });
        const { getByText } = render(() => <DiffTreeView tree={tree} />);
        expect(getByText(/no dependency tree available/i)).toBeDefined();
    });
});
