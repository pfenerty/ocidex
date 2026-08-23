// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Router } from "@solidjs/router";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";
import { useLicenses } from "~/api/queries";
import Licenses from "~/pages/Licenses";

vi.mock("~/api/queries", () => ({
    useLicenses: vi.fn(),
}));

const mockUseLicenses = vi.mocked(useLicenses);

// The router is real, not stubbed. All three filters are URL state now, and a
// stub would let a broken read or write pass unnoticed — which is the whole
// defect this story exists to fix.

// Vitest runs without globals, so the testing library cannot register its own
// afterEach. Without this, a Toolbar left mounted commits its pending debounce
// into the next test's URL.
afterEach(cleanup);

interface QueryParams {
    name?: string;
    spdx_id?: string;
    category?: string;
    limit?: number;
    offset?: number;
}

function renderAt(path: string) {
    // Hold the accessor rather than a snapshot: it reads the page's state, so
    // calling it after an interaction reports what the real hook would query.
    let latest: () => QueryParams = () => ({});
    mockUseLicenses.mockImplementation(((params: () => QueryParams) => {
        latest = params;
        return {
            data: { data: [], pagination: { total: 0, limit: 20, offset: 0 } },
            isFetching: false,
            isError: false,
            error: null,
        };
    }) as unknown as typeof useLicenses);

    window.history.replaceState({}, "", path);
    const rendered = render(() => (
        <Router root={(props) => <>{props.children}</>}>
            {[{ path: "/licenses", component: () => <Licenses /> }]}
        </Router>
    ));
    return { ...rendered, params: () => latest() };
}

function textInputs(container: HTMLElement): HTMLInputElement[] {
    return [...container.querySelectorAll<HTMLInputElement>('.search-bar input[type="text"]')];
}

describe("Licenses filters live in the URL", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("seeds all three filters from the query string", () => {
        const { container, params } = renderAt("/licenses?name=Apache&spdx=MIT&category=copyleft");
        expect(textInputs(container).map((i) => i.value)).toEqual(["Apache", "MIT"]);
        const active = container.querySelectorAll(".tab-bar button.active");
        expect(active.length).toBe(1);
        expect(active[0].textContent).toBe("Copyleft");
        expect(params().name).toBe("Apache");
        expect(params().spdx_id).toBe("MIT");
        expect(params().category).toBe("copyleft");
    });

    // The two boxes already re-queried on every keystroke — the "Search" button
    // only reset the offset — so the pause is the actual behaviour change.
    it("waits for a pause before committing a keystroke", async () => {
        vi.useFakeTimers();
        try {
            const { container } = renderAt("/licenses");
            const [name] = textInputs(container);
            for (const v of ["A", "Ap", "Apa"]) {
                fireEvent.input(name, { target: { value: v } });
            }
            expect(window.location.search).toBe("");
            vi.advanceTimersByTime(300);
        } finally {
            vi.useRealTimers();
        }
        await waitFor(() => {
            expect(window.location.search).toBe("?name=Apa");
        });
    });

    it("composes the category strip with the text filters", async () => {
        const { container, params } = renderAt("/licenses?name=Apache");
        const [permissive] = [...container.querySelectorAll(".tab-bar button")].filter(
            (b) => b.textContent === "Permissive",
        );
        fireEvent.click(permissive);
        await waitFor(() => {
            expect(params().category).toBe("permissive");
        });
        // The name filter survives the category click rather than being reset
        // by it — the two are independent dimensions of the same list.
        expect(params().name).toBe("Apache");
        expect(window.location.search).toContain("name=Apache");
    });

    it("drops the category param for All rather than storing an empty one", async () => {
        const { container } = renderAt("/licenses?category=copyleft");
        const [all] = [...container.querySelectorAll(".tab-bar button")].filter(
            (b) => b.textContent === "All",
        );
        fireEvent.click(all);
        await waitFor(() => {
            expect(window.location.search).not.toContain("category");
        });
    });

    it("clears both text filters at once, leaving the category alone", async () => {
        const { container, params } = renderAt("/licenses?name=Apache&spdx=MIT&category=copyleft");
        const clear = [...container.querySelectorAll(".search-bar button")].find(
            (b) => b.textContent === "Clear",
        );
        expect(clear).toBeDefined();
        if (clear === undefined) return;
        fireEvent.click(clear);
        await waitFor(() => {
            expect(params().name).toBeUndefined();
        });
        expect(params().spdx_id).toBeUndefined();
        // Clear belongs to the Toolbar, so it clears the Toolbar's fields. The
        // category is the TabBar's dimension and keeps its own control.
        expect(params().category).toBe("copyleft");
        expect(textInputs(container).map((i) => i.value)).toEqual(["", ""]);
    });
});
