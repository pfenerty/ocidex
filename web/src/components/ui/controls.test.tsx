// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { MemoryRouter, Route } from "@solidjs/router";
import { Segmented, TabBar } from "~/components/ui";

/**
 * Three selection controls, one job each (ocidex-iz0r.5): TabBar nav switches
 * what you look at, Segmented switches how it is shown, TabBar filter narrows.
 */
describe("TabBar semantics", () => {
    it("is a tablist of tabs when it switches a panel in place", () => {
        const { container } = render(() => (
            <TabBar tabs={[{ id: "a", label: "A" }, { id: "b", label: "B" }]} active="b" onSelect={vi.fn()} />
        ));
        expect(container.querySelector('[role="tablist"]')).not.toBeNull();
        const tabs = [...container.querySelectorAll('[role="tab"]')];
        expect(tabs.map((t) => t.getAttribute("aria-selected"))).toEqual(["false", "true"]);
    });

    it("marks the current page, not a tab, when its entries are links", () => {
        const { container } = render(() => (
            <MemoryRouter>
                <Route path="/" component={() => <TabBar tabs={[{ id: "a", label: "A", href: "/a" }]} active="a" />} />
            </MemoryRouter>
        ));
        expect(container.querySelector("a")?.getAttribute("aria-current")).toBe("page");
        expect(container.querySelector('[role="tablist"]')).toBeNull();
    });
});

describe("Segmented", () => {
    it("reports the pressed option and calls back with the chosen id", () => {
        const onChange = vi.fn();
        const { getByText, container } = render(() => (
            <Segmented
                label="Package view"
                options={[{ id: "tree", label: "Tree" }, { id: "list", label: "List" }]}
                value="tree"
                onChange={onChange}
            />
        ));
        expect(container.querySelector('[role="group"]')?.getAttribute("aria-label")).toBe("Package view");
        expect(getByText("Tree").getAttribute("aria-pressed")).toBe("true");
        fireEvent.click(getByText("List"));
        expect(onChange).toHaveBeenCalledWith("list");
    });
});

describe("view-mode toggles go through Segmented", () => {
    it("no ButtonGroup holds a pressed-toggle Button", () => {
        const src = resolve(__dirname, "../..");
        const offenders: string[] = [];
        const walk = (dir: string) => {
            for (const e of readdirSync(dir)) {
                const full = join(dir, e);
                if (statSync(full).isDirectory()) walk(full);
                else if (e.endsWith(".tsx") && !e.includes(".test.")) {
                    const code = readFileSync(full, "utf-8");
                    for (const m of code.matchAll(/<ButtonGroup[\s\S]*?<\/ButtonGroup>/g)) {
                        if (/\sactive=\{/.test(m[0])) offenders.push(full.slice(src.length + 1));
                    }
                }
            }
        };
        walk(src);
        expect(offenders).toEqual([]);
    });
});
