// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { Router } from "@solidjs/router";
import { render, cleanup, fireEvent } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { DependencyTreeView } from "./DependencyTreeView";

afterEach(cleanup);

/** A component node; `crit` > 0 makes it vulnerable. */
function node(name: string, crit = 0): ComponentSummary {
    return {
        id: name,
        sbomId: "s1",
        name,
        type: "library",
        bomRef: name,
        purl: `pkg:golang/${name}@1.0.0`,
        criticalCount: crit,
    } as ComponentSummary;
}

function edge(from: string, to: string): DependencyEdge {
    return { from, to };
}

/*  app ─┬─ clean-lib ── clean-leaf          (no findings anywhere)
        └─ mid ── vuln-leaf                 (a finding two levels down)
    other-root ── also-clean                (a whole branch with nothing)  */
const graph = {
    roots: ["app", "other-root"],
    nodes: [
        node("app"), node("clean-lib"), node("clean-leaf"),
        node("mid"), node("vuln-leaf", 3),
        node("other-root"), node("also-clean"),
    ],
    edges: [
        edge("app", "clean-lib"), edge("clean-lib", "clean-leaf"),
        edge("app", "mid"), edge("mid", "vuln-leaf"),
        edge("other-root", "also-clean"),
    ],
};

function renderTree(vulnerableOnly: boolean) {
    return render(() => (
        <Router root={(r) => <>{r.children}</>}>
            {[{ path: "/", component: () => <DependencyTreeView graph={graph} vulnerableOnly={vulnerableOnly} /> }]}
        </Router>
    ));
}

/** Package names in the order the tree draws them. */
function names(container: HTMLElement): string[] {
    return [...container.querySelectorAll("tbody tr")].map(
        (r) => r.querySelector(".tree-name a, .tree-name > span:nth-child(2)")?.textContent.trim() ?? "",
    );
}

describe("DependencyTreeView vulnerable-only filter", () => {
    it("draws only the roots when off, as it always has", () => {
        const { container } = renderTree(false);
        expect(names(container)).toEqual(["app", "other-root"]);
    });

    // The point of the filter: the finding is two levels down, and without the
    // auto-expand the reader would see the same two roots and have to guess
    // which one to open.
    it("opens the path to the vulnerable package with no clicks", () => {
        const [on, setOn] = createSignal(false);
        const { container } = render(() => (
            <Router root={(r) => <>{r.children}</>}>
                {[{ path: "/", component: () => <DependencyTreeView graph={graph} vulnerableOnly={on()} /> }]}
            </Router>
        ));
        expect(names(container)).toEqual(["app", "other-root"]);
        setOn(true);
        expect(names(container)).toEqual(["app", "mid", "vuln-leaf"]);
    });

    // "Rather than hiding structure": the ancestry survives, because the depth
    // is what says which direct dependency pulled the vulnerable one in.
    it("keeps the unaffected ancestors of a vulnerable package", () => {
        const { container } = renderTree(true);
        const rows = [...container.querySelectorAll("tbody tr .tree-name")];
        expect(rows.map((r) => (r as HTMLElement).style.getPropertyValue("--depth"))).toEqual(["0", "1", "2"]);
    });

    it("drops branches that lead to nothing", () => {
        const { container } = renderTree(true);
        const drawn = names(container);
        for (const gone of ["other-root", "also-clean", "clean-lib", "clean-leaf"]) {
            expect(drawn).not.toContain(gone);
        }
    });

    // A twisty over a branch whose children were all filtered away opens onto
    // nothing, and a child-count badge that quotes the unfiltered number
    // contradicts the rows beneath it.
    it("counts only the children it will actually draw", () => {
        const { container } = renderTree(true);
        const appRow = container.querySelector("tbody tr");
        expect(appRow?.querySelector(".badge")?.textContent).toBe("1"); // mid, not mid + clean-lib
        const leafRow = [...container.querySelectorAll("tbody tr")][2];
        expect(leafRow.querySelector(".tree-twisty")?.textContent).toBe("");
    });

    it("says so when nothing in the graph is vulnerable", () => {
        const clean = { roots: ["a"], nodes: [node("a"), node("b")], edges: [edge("a", "b")] };
        const { container } = render(() => (
            <Router root={(r) => <>{r.children}</>}>
                {[{ path: "/", component: () => <DependencyTreeView graph={clean} vulnerableOnly /> }]}
            </Router>
        ));
        expect(container.textContent).toContain("No vulnerable dependencies");
    });

    // A circular dependency must not send the path walk into infinite recursion.
    it("survives a cycle on the path to a finding", () => {
        const cyclic = {
            roots: ["a"],
            nodes: [node("a"), node("b"), node("c", 1)],
            edges: [edge("a", "b"), edge("b", "a"), edge("b", "c")],
        };
        const { container } = render(() => (
            <Router root={(r) => <>{r.children}</>}>
                {[{ path: "/", component: () => <DependencyTreeView graph={cyclic} vulnerableOnly /> }]}
            </Router>
        ));
        expect(names(container)).toContain("c");
    });

    it("still lets the reader collapse a path the filter opened", () => {
        const { container } = renderTree(true);
        fireEvent.click(must(container.querySelector("tbody tr"), "the root row"));
        expect(names(container)).toEqual(["app"]);
    });
});

function must<T>(el: T | null | undefined, what: string): T {
    if (el === null || el === undefined) throw new Error(`expected ${what} in the tree`);
    return el;
}
