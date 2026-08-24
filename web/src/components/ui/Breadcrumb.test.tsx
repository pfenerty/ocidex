// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { Breadcrumb } from "./Breadcrumb";
import type { JSX } from "solid-js";

// The real router is not needed to assert what <A> emits; it renders an anchor
// with the href it was given, which is exactly what a crumb's contract is.
import { Router } from "@solidjs/router";

function renderTrail(items: Parameters<typeof Breadcrumb>[0]["items"]): HTMLElement {
    const { container } = render(() => (
        <Router root={(p): JSX.Element => p.children}>
            {[{ path: "*", component: () => <Breadcrumb items={items} /> }]}
        </Router>
    ));
    return container;
}

describe("Breadcrumb", () => {
    it("links every crumb that has an href", () => {
        const c = renderTrail([
            { label: "Artifacts", href: "/artifacts" },
            { label: "nginx", href: "/artifacts/1" },
            { label: "1.25" },
        ]);
        const hrefs = [...c.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(hrefs).toEqual(["/artifacts", "/artifacts/1"]);
    });

    // A link to the page you are on is a link that does nothing, and it invites
    // a click that appears to fail.
    it("renders the last crumb as text, not a link", () => {
        const c = renderTrail([
            { label: "Artifacts", href: "/artifacts" },
            { label: "nginx" },
        ]);
        expect(c.textContent).toContain("nginx");
        expect([...c.querySelectorAll("a")].some((a) => a.textContent === "nginx")).toBe(false);
    });

    it("puts a separator between crumbs and not before the first", () => {
        const c = renderTrail([
            { label: "A", href: "/a" },
            { label: "B", href: "/b" },
            { label: "C" },
        ]);
        expect(c.querySelectorAll(".separator").length).toBe(2);
        expect(c.firstElementChild?.classList.contains("separator")).toBe(false);
    });

    it("gives a mono crumb the mono face, whether or not it links", () => {
        const c = renderTrail([
            { label: "v1", href: "/v1", mono: true },
            { label: "sha256:ab", mono: true },
        ]);
        expect(c.querySelectorAll(".font-mono").length).toBe(2);
    });

    // A "not found" page has no subject to name, so its leaf label is absent.
    // Rendering the separator anyway leaves a trail ending in "Artifacts /".
    it("drops a crumb with nothing to name, separator included", () => {
        const c = renderTrail([
            { label: "Artifacts", href: "/artifacts" },
            { label: undefined },
        ]);
        expect(c.querySelectorAll(".separator").length).toBe(0);
        expect(c.textContent.trim()).toBe("Artifacts");
    });

    it("drops a crumb whose label resolved to an empty string", () => {
        const c = renderTrail([
            { label: "Licenses", href: "/licenses" },
            { label: "" },
        ]);
        expect(c.querySelectorAll(".separator").length).toBe(0);
    });

    it("renders a single crumb with no separator at all", () => {
        const c = renderTrail([{ label: "Clusters" }]);
        expect(c.querySelectorAll(".separator").length).toBe(0);
    });
});
