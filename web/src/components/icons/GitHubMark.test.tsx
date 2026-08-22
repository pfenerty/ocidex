// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { GitHubMark } from "./GitHubMark";

afterEach(cleanup);

function svg(container: HTMLElement): SVGSVGElement {
    const el = container.querySelector("svg");
    if (el === null) throw new Error("no svg rendered");
    return el;
}

describe("GitHubMark", () => {
    it("defaults to 16px, the size both sidebar call sites used", () => {
        const { container } = render(() => <GitHubMark />);
        expect(svg(container).getAttribute("width")).toBe("16");
        expect(svg(container).getAttribute("height")).toBe("16");
    });

    it("takes a size the way a lucide icon does", () => {
        const { container } = render(() => <GitHubMark size={14} />);
        expect(svg(container).getAttribute("height")).toBe("14");
    });

    it("keeps the viewBox fixed when resized", () => {
        // The path is authored against a 16-unit box; scaling is the viewport's
        // job, so a caller passing size={14} must not shrink the coordinates.
        const { container } = render(() => <GitHubMark size={14} />);
        expect(svg(container).getAttribute("viewBox")).toBe("0 0 16 16");
    });

    it("inherits its colour from the surrounding link or chip", () => {
        const { container } = render(() => <GitHubMark />);
        expect(svg(container).getAttribute("fill")).toBe("currentColor");
    });

    it("is hidden from assistive tech, since every call site has a text label", () => {
        const { container } = render(() => <GitHubMark />);
        expect(svg(container).getAttribute("aria-hidden")).toBe("true");
    });
});

describe("the mark is not inlined anywhere else", () => {
    // Three copies existed before this component, and two of them had drifted
    // apart in arc precision. A fourth would drift too.
    it.each(["components/Layout.tsx", "pages/Login.tsx"])("%s uses the component", (rel) => {
        const src = readFileSync(join(__dirname, "..", "..", rel), "utf-8");
        expect(src).not.toContain("M8 0C3.58");
        expect(src).toContain("<GitHubMark");
    });
});
