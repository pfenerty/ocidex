// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { createSignal } from "solid-js";
import { Router } from "@solidjs/router";
import { render, cleanup, fireEvent } from "@solidjs/testing-library";
import type { ComponentSummary } from "~/api/client";
import { PackagesTab } from "./PackagesTab";

afterEach(cleanup);

function comps(n: number, type = "golang"): ComponentSummary[] {
    return Array.from({ length: n }, (_, i) => ({
        id: `c${i}`,
        sbomId: "s1",
        name: `pkg-${i}`,
        type,
        isDirect: true,
        purl: `pkg:${type}/pkg-${i}@1.0.0`,
    }));
}

// View mode is owned by the page, not the tab (ocidex-7gf7.9), so the harness
// stands in for it. Every other prop stays optional: these tests are about what
// the tab renders, not about which of its inputs the page happens to pass.
type TabProps = Partial<Parameters<typeof PackagesTab>[0]> & {
    components: ComponentSummary[];
};

// The package rows link out via ComponentNameCell's <A>, so the tab only
// mounts inside a router.
function renderTab(props: TabProps) {
    return render(() => {
        const [view, setView] = createSignal<"tree" | "list">("tree");
        return (
            <Router root={(r) => <>{r.children}</>}>
                {[
                    {
                        path: "/",
                        component: () => (
                            <PackagesTab
                                viewMode={view()}
                                onViewMode={setView}
                                {...props}
                            />
                        ),
                    },
                ]}
            </Router>
        );
    });
}

function must<T>(el: T | null | undefined, what: string): T {
    if (el === null || el === undefined) throw new Error(`expected ${what} in the packages tab`);
    return el;
}

/** Hover the count line and read the definition it explains. */
function explanation(container: HTMLElement): string {
    fireEvent.mouseEnter(must(container.querySelector<HTMLElement>(".tooltip-trigger"), "a tooltip trigger"));
    return must(document.querySelector(".tooltip-content"), "tooltip content").textContent;
}

/** The single figure the tab quotes, read off the rendered count line. */
function countLine(container: HTMLElement): string {
    return must(container.querySelector(".search-bar .text-muted"), "the count line").textContent.trim();
}

describe("PackagesTab package count", () => {
    // The page rendered three different package figures at once: the header's
    // component count (all components, files included), the band tile and tab
    // (the server's package count), and this line, which quoted the length of
    // the window loaded so far. A reader had no way to tell which was
    // authoritative. This tab now quotes the server's figure.
    it("quotes the SBOM total, not the number of rows loaded", () => {
        const { container } = renderTab({ components: comps(200), totalCount: 958, componentCount: 4193, hasMore: true });
        expect(countLine(container)).toBe("200 of 958 packages loaded");
    });

    it("drops the qualifier once every package is loaded", () => {
        const { container } = renderTab({ components: comps(958), totalCount: 958, componentCount: 4193 });
        expect(countLine(container)).toBe("958 packages");
    });

    it("falls back to the loaded rows when no total is supplied", () => {
        const { container } = renderTab({ components: comps(12) });
        expect(countLine(container)).toBe("12 packages");
    });

    it("counts a filtered view against the loaded rows and says so", () => {
        // Filtering is client-side over what has been loaded, so quoting a
        // filtered count against the 958 total would be a lie.
        const { container } = renderTab({ components: comps(200), totalCount: 958, componentCount: 4193, hasMore: true });
        const input = must(container.querySelector("input"), "the filter input");
        fireEvent.input(input, { target: { value: "pkg-1" } });
        expect(countLine(container)).toMatch(/^\d+ of 200 loaded packages$/);
    });

    it("excludes file entries from the packages it lists", () => {
        const withFiles = [...comps(3), ...comps(2, "file")];
        const { container } = renderTab({ components: withFiles, totalCount: 3, componentCount: 5 });
        expect(countLine(container)).toBe("3 packages");
    });
});

describe("PackagesTab count explanation", () => {
    it("reconciles packages against the SBOM's full component count", () => {
        const { container } = renderTab({ components: comps(958), totalCount: 958, componentCount: 4193 });
        const content = explanation(container);
        expect(content).toContain("excluding file entries");
        // The 4193 the header used to show is accounted for here rather than
        // left on screen contradicting the 958.
        expect(content).toContain("4193 components in total");
        expect(content).toContain("3235 of them files");
    });

    it("warns that filters only see loaded rows while more remain", () => {
        const { container } = renderTab({ components: comps(200), totalCount: 958, componentCount: 4193, hasMore: true });
        expect(explanation(container)).toContain("loaded rows only");
    });

    it("drops that warning once everything is loaded", () => {
        const { container } = renderTab({ components: comps(958), totalCount: 958, componentCount: 4193 });
        expect(explanation(container)).not.toContain("loaded rows only");
    });
});

describe("PackagesTab severity sort", () => {
    /** The clickable header cell for a column, by its label. */
    function header(container: HTMLElement, label: string): HTMLElement {
        const th = [...container.querySelectorAll("th")].find((h) => h.textContent.startsWith(label));
        return must(th, `a "${label}" column header`);
    }

    // Severity is server-sorted: the counts order the whole SBOM, not the 200
    // rows on screen. So the click has to leave the tab and reach the query.
    it("asks the page for a severity sort, worst first", () => {
        const calls: [string, string][] = [];
        const { container } = renderTab({
            components: comps(3),
            onSort: (key, dir) => calls.push([key, dir]),
        });
        fireEvent.click(header(container, "Vulns"));
        expect(calls).toEqual([["severity", "desc"]]);
    });

    it("flips to ascending on a second click", () => {
        const calls: [string, string][] = [];
        const { container } = renderTab({
            components: comps(3),
            sortBy: "severity",
            sortDir: "desc",
            onSort: (key, dir) => calls.push([key, dir]),
        });
        fireEvent.click(header(container, "Vulns"));
        expect(calls).toEqual([["severity", "asc"]]);
    });

    // Nothing else in this table has a server-side ordering, and offering a
    // client-side one over a partial window would sort 200 of 958 packages
    // while looking like it sorted the SBOM.
    it("makes no other column sortable", () => {
        const { container } = renderTab({ components: comps(3), onSort: () => undefined });
        // th-sortable is what marks a header clickable — a header without it
        // has no affordance, and handleSort ignores a column with no sortKey.
        expect(header(container, "Vulns").className).toContain("th-sortable");
        for (const label of ["Name", "Version", "Type", "Package URL"]) {
            expect(header(container, label).className).not.toContain("th-sortable");
        }
    });
});

describe("PackagesTab vulnerable-only toggle", () => {
    /** The shared toggle button. */
    function toggle(container: HTMLElement): HTMLButtonElement {
        const b = [...container.querySelectorAll("button")].find((x) => x.textContent === "Vulnerable only");
        return must(b, "the vulnerable-only toggle");
    }

    function rowNames(container: HTMLElement): string[] {
        return [...container.querySelectorAll("tbody tr")].map(
            (r) => must(r.querySelector("td"), "a name cell").textContent.trim(),
        );
    }

    /** comps() with a finding pinned onto one of them. */
    function withOneVulnerable(n = 3) {
        const list = comps(n);
        return list.map((c, i) => (i === 1 ? { ...c, criticalCount: 2 } : c));
    }

    it("narrows the list to packages with findings", () => {
        const { container } = renderTab({ components: withOneVulnerable() });
        expect(rowNames(container)).toHaveLength(3);
        fireEvent.click(toggle(container));
        expect(rowNames(container)).toEqual(["pkg-1"]);
    });

    it("is off until asked for", () => {
        const { container } = renderTab({ components: withOneVulnerable() });
        expect(toggle(container).getAttribute("aria-pressed")).toBe("false");
        expect(rowNames(container)).toHaveLength(3);
    });

    // The count line already says a filtered figure is quoted against the
    // loaded rows; the toggle is a filter like any other and must not escape it.
    it("counts the narrowed list against the loaded rows", () => {
        const { container } = renderTab({ components: withOneVulnerable(200), totalCount: 958, hasMore: true });
        fireEvent.click(toggle(container));
        expect(countLine(container)).toBe("1 of 200 loaded packages");
    });

    it("composes with the text filter rather than replacing it", () => {
        const list = comps(20).map((c, i) => (i % 2 === 0 ? { ...c, highCount: 1 } : c));
        const { container } = renderTab({ components: list });
        fireEvent.click(toggle(container));
        fireEvent.input(must(container.querySelector("input"), "the filter input"), { target: { value: "pkg-1" } });
        // pkg-1x that are even-numbered, i.e. carry a finding: 10, 12, 14, 16, 18.
        expect(rowNames(container)).toEqual(["pkg-10", "pkg-12", "pkg-14", "pkg-16", "pkg-18"]);
    });

    // Offering a filter that can only ever empty the table is worse than not
    // offering it: the reader reads the empty result as "the query is broken".
    it("is disabled when nothing loaded has a finding", () => {
        const { container } = renderTab({ components: comps(3) });
        expect(toggle(container).disabled).toBe(true);
    });

    // It filters a question, not a widget. Switching view must not drop it —
    // which is why the button sits outside the list-only controls.
    it("stays applied across a view-mode switch", () => {
        const list = withOneVulnerable();
        const { container } = renderTab({
            components: list,
            depsGraph: { nodes: list, edges: [{ from: "pkg-0", to: "pkg-1" }] as never },
        });
        // Tree is the default when a graph is present; the toggle is still there.
        fireEvent.click(toggle(container));
        expect(toggle(container).getAttribute("aria-pressed")).toBe("true");
        const listBtn = must([...container.querySelectorAll("button")].find((b) => b.textContent === "List"), "the List button");
        fireEvent.click(listBtn);
        expect(toggle(container).getAttribute("aria-pressed")).toBe("true");
        expect(rowNames(container)).toEqual(["pkg-1"]);
    });
});

// The mode used to be a signal in this component, and the tab is mounted inside
// a QueryBoundary whose <Show ... keyed> remounts it every time the components
// query resolves a new object — which sorting a column does. So sorting threw
// the reader back into the tree. The mode is the page's now (ocidex-7gf7.9),
// and these tests pin that it is genuinely the page's: the tab renders what it
// is given and reports clicks rather than acting on them.
describe("PackagesTab view mode", () => {
    const graph = (list: ComponentSummary[]) => ({
        nodes: list,
        edges: [{ from: "pkg-0", to: "pkg-1" }] as never,
    });

    function viewButton(container: HTMLElement, label: string): HTMLButtonElement {
        return must(
            [...container.querySelectorAll("button")].find((b) => b.textContent === label),
            `the ${label} button`,
        );
    }

    it("renders the mode it is given rather than a default of its own", () => {
        const list = comps(3);
        const { container } = renderTab({
            components: list,
            depsGraph: graph(list),
            viewMode: "list",
        });
        expect(viewButton(container, "List").className).toContain("active");
        expect(container.querySelector("table")).not.toBeNull();
    });

    it("reports a switch upward instead of keeping the answer to itself", () => {
        const list = comps(3);
        const asked: string[] = [];
        const { container } = renderTab({
            components: list,
            depsGraph: graph(list),
            viewMode: "tree",
            onViewMode: (m) => asked.push(m),
        });
        fireEvent.click(viewButton(container, "List"));
        expect(asked).toEqual(["list"]);
        // Still the tree, because the parent owns the answer and this render
        // was never told otherwise.
        expect(container.querySelector("table")).toBeNull();
    });

    it("falls back to the list when there is no tree to show", () => {
        const { container } = renderTab({ components: comps(3), viewMode: "tree" });
        expect(container.querySelector("table")).not.toBeNull();
        expect([...container.querySelectorAll("button")].some((b) => b.textContent === "Tree")).toBe(false);
    });
});
