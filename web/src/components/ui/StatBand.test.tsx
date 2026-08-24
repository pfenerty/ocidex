// @vitest-environment happy-dom
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { StatBand, type StatTile } from "./StatBand";

afterEach(cleanup);

type Tab = "a" | "b";

const TILES: StatTile<Tab>[] = [
    { id: "a", head: "Alpha", value: 1, sub: "first" },
    { id: "b", head: "Beta", value: 2, sub: "second" },
];

function renderBand(tiles: StatTile<Tab>[], active?: Tab, onSelect?: (id: Tab) => void) {
    return render(() => <StatBand tiles={tiles} active={active} onSelect={onSelect} />);
}

describe("StatBand tile element", () => {
    it("renders a tile with an id as a button", () => {
        const { container } = renderBand(TILES);
        expect(container.querySelectorAll("button.tile").length).toBe(2);
    });

    it("renders a tile with an href as a link", () => {
        const { container } = renderBand([{ href: "/clusters/1", head: "Matched", value: 9 }]);
        const a = container.querySelector<HTMLAnchorElement>("a.tile");
        expect(a).not.toBeNull();
        expect(a?.getAttribute("href")).toBe("/clusters/1");
    });

    it("renders a tile with neither as a plain div", () => {
        const { container } = renderBand([{ head: "Vulnerabilities", value: 3 }]);
        // A tile that only reports a number must not look clickable.
        expect(container.querySelector("div.tile")).not.toBeNull();
        expect(container.querySelector("button.tile")).toBeNull();
        expect(container.querySelector("a.tile")).toBeNull();
    });
});

describe("StatBand selection", () => {
    it("marks only the active tile", () => {
        const { container } = renderBand(TILES, "b");
        const active = [...container.querySelectorAll(".tile.active")];
        expect(active.length).toBe(1);
        expect(active[0].textContent).toContain("Beta");
    });

    it("reports the tile id on click", () => {
        const onSelect = vi.fn();
        const { container } = renderBand(TILES, "a", onSelect);
        fireEvent.click([...container.querySelectorAll("button.tile")][1]);
        expect(onSelect).toHaveBeenCalledWith("b");
    });

    it("never marks a non-selectable tile active", () => {
        const { container } = renderBand([{ head: "Vulnerabilities", value: 3 }], undefined);
        expect(container.querySelector(".tile.active")).toBeNull();
    });
});

describe("StatBand layout", () => {
    // How many tiles fit on a row is a CSS question, not a prop — the band
    // takes any number. Two hardcoded column counts have already shipped wrong:
    // a literal four, which wrapped the SBOM band's fifth tile onto a row of
    // its own, and then a count derived from the tile count, which made six
    // tiles ~100px wide — narrower than the "Verification failed" badge inside
    // one, so every tile overflowed its own box. Neither failed a unit test,
    // because a grid that lays out badly is not an assertion failure. So this
    // asserts the stylesheet, the way fontContract and typeScale do.
    const css = readFileSync(resolve(__dirname, "../TileBand.css"), "utf8");
    const bandRule = /\.tile-band\s*\{[^}]*\}/.exec(css)?.[0] ?? "";

    it("fits tiles to the available width instead of a fixed column count", () => {
        expect(bandRule).toMatch(/grid-template-columns:\s*repeat\(\s*auto-fit/);
    });

    it("gives every track a floor wide enough for a two-word badge", () => {
        expect(bandRule).toMatch(/minmax\(\s*\d+(\.\d+)?rem\s*,\s*1fr\s*\)/);
    });

    it("lets a tile shrink below its content width", () => {
        // Grid items floor at min-content unless told otherwise, and `.tile-sub`
        // is `white-space: nowrap` — without this the band runs off the right
        // edge of the page rather than ellipsing the sub-line.
        const tileRule = /\.tile\s*\{[^}]*\}/.exec(css)?.[0] ?? "";
        expect(tileRule).toMatch(/min-width:\s*0/);
    });

    it("keeps the sub-line a block, so its ellipsis actually applies", () => {
        // `text-overflow` only works on a block container's own inline content.
        // `.tile-sub` was `display: flex`, so the whole
        // overflow/text-overflow/nowrap trio was inert and an over-long sub was
        // cut hard mid-word — Home's "images, binaries and libraries" rendered
        // as "images, binaries and libi" (ocidex-ag4q.58). The two properties
        // have to be asserted together: either one alone is silently useless.
        const subRule = /\.tile-sub\s*\{[^}]*\}/.exec(css.replace(/\/\*[\s\S]*?\*\//g, ""))?.[0] ?? "";
        expect(subRule).toMatch(/text-overflow:\s*ellipsis/);
        expect(subRule).not.toMatch(/display:\s*(inline-)?flex/);
    });

    it("appends a caller class rather than replacing tile-band", () => {
        const { container } = render(() => <StatBand tiles={TILES} class="mb-4" />);
        expect(container.querySelector(".tile-band")?.className).toBe("tile-band mb-4");
    });
});

describe("StatBand tile content", () => {
    it("omits the sub-line when there is none", () => {
        const { container } = renderBand([{ head: "Alpha", value: 1 }]);
        expect(container.querySelector(".tile-sub")).toBeNull();
    });

    it("composes valueClass with tile-value rather than replacing it", () => {
        const { container } = renderBand([{ head: "Alpha", value: 1, valueClass: "badge" }]);
        const v = container.querySelector(".tile-value");
        expect(v?.className).toContain("tile-value");
        expect(v?.className).toContain("badge");
    });

    it("renders the icon inside the head row", () => {
        const { container } = renderBand([
            { head: "Alpha", value: 1, icon: <svg data-testid="icon" /> },
        ]);
        expect(container.querySelector(".tile-head svg")).not.toBeNull();
    });
});
