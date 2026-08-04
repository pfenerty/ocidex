// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { useDashboardStats } from "~/api/queries";
import Home from "~/pages/Home";
import type { JSX } from "solid-js";

vi.mock("~/api/queries", () => ({
    useDashboardStats: vi.fn(),
}));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element }) => (
        <a href={props.href}>{props.children}</a>
    ),
}));

const mockUseStats = vi.mocked(useDashboardStats);

interface StatsQuery {
    isLoading: boolean;
    isError: boolean;
    data:
        | {
              artifact_count: number;
              package_count: number;
              license_count: number;
              vuln_count: number;
              warming?: boolean;
          }
        | undefined;
}

function renderHome(query: StatsQuery) {
    // The component only reads these three fields off the query.
    mockUseStats.mockReturnValue(query as unknown as ReturnType<typeof useDashboardStats>);
    return render(() => <Home />);
}

describe("Home catalog stats", () => {
    it("renders the counts once stats load", () => {
        const { getByText } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 38,
                package_count: 107868,
                license_count: 545,
                vuln_count: 12,
            },
        });
        expect(getByText("38 artifacts")).toBeDefined();
        expect(getByText("107,868 packages")).toBeDefined();
    });

    // Regression: the stats query times out against a cold cache, and a bare
    // <Show> rendered that as nothing at all — visually identical to an empty
    // catalog, which is why the failure went unnoticed in production.
    it("says stats are unavailable rather than rendering nothing on error", () => {
        const { container } = renderHome({ isLoading: false, isError: true, data: undefined });
        expect(container.textContent).toContain("Catalog stats are unavailable");
    });

    it("shows a placeholder while stats are still loading", () => {
        const { container } = renderHome({ isLoading: true, isError: false, data: undefined });
        expect(container.querySelector(".skeleton")).not.toBeNull();
        expect(container.textContent).not.toContain("Catalog stats are unavailable");
    });

    // A warming response is a successful 200 whose counts are all zero
    // placeholders — the snapshot is computed out of band by the background
    // warmer. Rendering it verbatim claims an empty catalog.
    it("keeps the placeholder when the server reports it is still warming", () => {
        const { container } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 0,
                package_count: 0,
                license_count: 0,
                vuln_count: 0,
                warming: true,
            },
        });
        expect(container.querySelector(".skeleton")).not.toBeNull();
        expect(container.textContent).not.toContain("0 artifacts");
    });
});
