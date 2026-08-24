// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRenderEffect } from "solid-js";
import { Router, Route } from "@solidjs/router";
import { render, fireEvent } from "@solidjs/testing-library";
import { useComponent, useComponentVersions, useComponentVulns } from "~/api/queries";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import ComponentOverview from "~/pages/ComponentOverview";

vi.mock("~/api/queries", () => ({
    useComponent: vi.fn(),
    useComponentVersions: vi.fn(),
    useComponentVulns: vi.fn(),
}));

const mockVersions = vi.mocked(useComponentVersions);
const mockComponent = vi.mocked(useComponent);
const mockVulns = vi.mocked(useComponentVulns);

function queryState(over: Record<string, unknown>) {
    return {
        isLoading: false,
        isFetching: false,
        isError: false,
        error: null,
        data: undefined,
        ...over,
    } as never;
}

// One row per SBOM occurrence, which is what the endpoint returns and what
// `pagination.total` counts.
function row(i: number) {
    return {
        id: `c${i}`,
        sbomId: `sbom-${i}`,
        artifactId: `art-${i}`,
        artifactName: `app-${i}`,
        name: "lodash",
        version: `4.17.${i}`,
        type: "library",
        purl: `pkg:npm/lodash@4.17.${i}`,
    };
}

// The params the page most recently asked for, so the assertions can check the
// request window rather than only what came back.
let lastParams: { limit?: number; offset?: number } | undefined;

function renderAt(path: string) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            <Route path="/components/overview" component={ComponentOverview} />
        </Router>
    ));
}

describe("ComponentOverview pagination", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        lastParams = undefined;
        mockComponent.mockReturnValue(queryState({}));
        mockVulns.mockReturnValue(queryState({}));
    });

    function withVersions(total: number, offset: number, count = DEFAULT_PAGE_SIZE) {
        mockVersions.mockImplementation((params) => {
            // Read through an effect, not once at call time: the hook is invoked
            // during setup, so a bare `params()` would freeze the captured window
            // at mount and a page change would look like a no-op.
            createRenderEffect(() => {
                lastParams = params();
            });
            return queryState({
                data: {
                    versions: Array.from({ length: count }, (_, i) => row(offset + i)),
                    pagination: { total, limit: DEFAULT_PAGE_SIZE, offset },
                },
            });
        });
    }

    it("asks for a bounded window instead of the whole version history", () => {
        withVersions(4210, 0);
        renderAt("/components/overview?name=lodash");

        expect(lastParams?.limit).toBe(DEFAULT_PAGE_SIZE);
        expect(lastParams?.offset).toBe(0);
    });

    it("renders Pagination and advances the offset", () => {
        withVersions(4210, 0);
        const { container } = renderAt("/components/overview?name=lodash");

        expect(container.querySelector(".pagination")).toBeTruthy();
        // The controls are «« « n/N » »»; "»" is next-page. Scoped to
        // .pagination-controls so the page body's own glyphs can never match.
        const [next] = [...container.querySelectorAll(".pagination-controls button")].filter(
            (b) => b.textContent.trim() === "»",
        );
        expect(next).toBeDefined();
        fireEvent.click(next);
        expect(lastParams?.offset).toBe(DEFAULT_PAGE_SIZE);
    });

    it("qualifies the header counts once the list is paginated", () => {
        withVersions(4210, 0);
        const { container } = renderAt("/components/overview?name=lodash");

        // The old header said "N versions across N SBOMs" using the row count,
        // which under pagination silently means "on this page" while reading as
        // the whole corpus.
        expect(container.textContent).toContain("on this page");
        expect(container.textContent).toContain("4210 SBOMs in total");
    });

    it("keeps the plain header and no controls when everything fits on one page", () => {
        withVersions(3, 0, 3);
        const { container } = renderAt("/components/overview?name=lodash");

        expect(container.querySelector(".pagination")).toBeNull();
        expect(container.textContent).not.toContain("on this page");
        expect(container.textContent).toContain("3 versions across 3 SBOMs");
    });
});
