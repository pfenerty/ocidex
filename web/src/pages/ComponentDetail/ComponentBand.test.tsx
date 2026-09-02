// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { Router } from "@solidjs/router";
import { ComponentBand, type CorpusCounts } from "./ComponentBand";
import type { ComponentDetail } from "~/api/client";

afterEach(cleanup);

const detail = (over: Partial<ComponentDetail> = {}): ComponentDetail =>
    ({
        id: "c1",
        sbomId: "s1",
        name: "zlib",
        type: "library",
        version: "1.3.1",
        vulnCount: 3,
        criticalCount: 1,
        highCount: 2,
        mediumCount: 0,
        lowCount: 0,
        unknownCount: 0,
        licenses: [{ id: "l1", name: "Zlib License", spdxId: "Zlib" }],
        ...over,
    }) as ComponentDetail;

const counts: CorpusCounts = { artifactCount: 12, versionCount: 37, sbomCount: 4210 };

function renderBand(
    d: ComponentDetail = detail(),
    // Not a defaulted parameter: passing an explicit `undefined` to one takes
    // the default, which is exactly the case the loading test needs to exercise.
    opts: { counts?: CorpusCounts | undefined; selected?: string[] } = {},
) {
    const c = "counts" in opts ? opts.counts : counts;
    const selected = opts.selected ?? [];
    const { container } = render(() => (
        <Router root={(p) => <>{p.children}</>}>
            {[
                {
                    path: "/",
                    component: () => (
                        <ComponentBand
                            detail={d}
                            counts={c}
                            vulns={{
                                critical: d.criticalCount ?? 0,
                                high: d.highCount ?? 0,
                                medium: d.mediumCount ?? 0,
                                low: d.lowCount ?? 0,
                                unknown: d.unknownCount ?? 0,
                                total: d.vulnCount ?? 0,
                            }}
                            active="details"
                            onSelect={(t) => selected.push(t)}
                        />
                    ),
                },
            ]}
        </Router>
    ));
    const tiles = [...container.querySelectorAll(".tile")];
    return {
        container,
        tiles,
        // The label without its scope caption, which the head has carried since
        // ocidex-7gf7.7; `scope` reads the caption on its own.
        head: (i: number) => {
            const h = tiles[i].querySelector(".tile-head");
            if (h === null) return undefined;
            const copy = h.cloneNode(true) as HTMLElement;
            copy.querySelector(".tile-scope")?.remove();
            return copy.textContent;
        },
        scope: (i: number) => tiles[i].querySelector(".tile-scope")?.textContent,
        value: (i: number) => tiles[i].querySelector(".tile-value")?.textContent,
        sub: (i: number) => tiles[i].querySelector(".tile-sub")?.textContent,
    };
}

describe("ComponentBand", () => {
    // The whole point of the band: these two numbers describe the corpus, and
    // a component row is scoped to one SBOM, so neither can be read off the
    // page the reader is on.
    // The band mixes two scopes: the first two tiles count the whole corpus,
    // the last two describe the one component row on screen. Rendered without
    // labels they read as one set, and "used by 12" beside "2 licenses" invites
    // the conclusion that the licences are those 12 artifacts' licences
    // (ocidex-7gf7.7).
    it("labels which of its tiles are corpus-wide and which are not", () => {
        const b = renderBand();
        expect(b.scope(0)).toBe("corpus-wide");
        expect(b.scope(1)).toBe("corpus-wide");
        expect(b.scope(2)).toBe("this version");
        expect(b.scope(3)).toBe("this version");
    });

    it("reports the corpus-wide artifact and version counts, not the page's", () => {
        const b = renderBand();
        expect(b.head(0)).toBe("Used by");
        expect(b.value(0)).toBe("12");
        expect(b.sub(0)).toContain("4210 SBOMs");
        expect(b.head(1)).toBe("Versions");
        expect(b.value(1)).toBe("37");
    });

    // A 0 here would read as "used nowhere" about a component we are looking at
    // inside an SBOM that demonstrably contains it.
    it("shows a dash, never a zero, while the counts are still loading", () => {
        const b = renderBand(detail(), { counts: undefined });
        expect(b.value(0)).toBe("—");
        expect(b.value(1)).toBe("—");
        expect(b.sub(0)).toBe("artifacts");
    });

    it("sends both corpus tiles to the overview page, group included", () => {
        const b = renderBand(detail({ name: "crypto", group: "golang.org/x" }));
        const hrefs = b.tiles.slice(0, 2).map((t) => t.getAttribute("href"));
        expect(hrefs[0]).toBe("/components/overview?name=crypto&group=golang.org%2Fx");
        expect(hrefs[1]).toBe(hrefs[0]);
    });

    it("names the licence when there is exactly one, and counts them otherwise", () => {
        expect(renderBand().sub(2)).toBe("Zlib");
        const two = renderBand(
            detail({
                licenses: [
                    { id: "l1", name: "MIT", spdxId: "MIT" },
                    { id: "l2", name: "Apache-2.0", spdxId: "Apache-2.0" },
                ],
            }),
        );
        expect(two.value(2)).toBe("2");
        expect(two.sub(2)).toBe("declared");
    });

    // The two instance-scoped tiles have a tab to open; the corpus ones have a
    // page. Neither may be a dead button.
    it("opens a tab from the licences and vulnerabilities tiles", () => {
        const selected: string[] = [];
        const b = renderBand(detail(), { selected });
        (b.tiles[2] as HTMLElement).click();
        (b.tiles[3] as HTMLElement).click();
        expect(selected).toEqual(["licenses", "vulns"]);
        expect(b.tiles.map((t) => t.tagName)).toEqual(["A", "A", "BUTTON", "BUTTON"]);
    });

    it("carries the worst severity present, not just the total", () => {
        const b = renderBand();
        expect(b.value(3)).toBe("3");
        expect(b.sub(3)).toContain("1 critical");
    });
});
