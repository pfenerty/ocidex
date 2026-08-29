// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
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

type TabProps = Parameters<typeof PackagesTab>[0];

// The package rows link out via ComponentNameCell's <A>, so the tab only
// mounts inside a router.
function renderTab(props: TabProps) {
    return render(() => (
        <Router root={(r) => <>{r.children}</>}>
            {[{ path: "/", component: () => <PackagesTab {...props} /> }]}
        </Router>
    ));
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
