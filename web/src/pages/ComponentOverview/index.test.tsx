// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRenderEffect } from "solid-js";
import { Router, Route } from "@solidjs/router";
import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { useComponent, useComponentVersions, useComponentVersionSummaries, useComponentVulns } from "~/api/queries";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import ComponentOverview from "~/pages/ComponentOverview";

vi.mock("~/api/queries", () => ({
    useComponent: vi.fn(),
    useComponentVersions: vi.fn(),
    useComponentVersionSummaries: vi.fn(),
    useComponentVulns: vi.fn(),
}));

const mockVersions = vi.mocked(useComponentVersions);
const mockSummaries = vi.mocked(useComponentVersionSummaries);
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

// One row per distinct version, which is what the summaries endpoint returns
// and what its `pagination.total` counts.
function summary(i: number) {
    return {
        version: `4.17.${i}`,
        type: "library",
        purl: `pkg:npm/lodash@4.17.${i}`,
        sbomCount: 3,
        artifactCount: 2,
    };
}

// One row per SBOM occurrence: the drill-down into a single version.
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
        mockVersions.mockReturnValue(queryState({}));
        mockSummaries.mockImplementation((params) => {
            // Read through an effect, not once at call time: the hook is invoked
            // during setup, so a bare `params()` would freeze the captured window
            // at mount and a page change would look like a no-op.
            createRenderEffect(() => {
                lastParams = params();
            });
            return queryState({
                data: {
                    versions: Array.from({ length: count }, (_, i) => summary(offset + i)),
                    pagination: { total, limit: DEFAULT_PAGE_SIZE, offset },
                    sbomCount: 4286,
                    artifactCount: 20,
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

    it("pages by version and states whole-corpus counts in the header", () => {
        // Paging occurrences and grouping them by version showed "1 version on
        // this page · 7482 SBOMs in total" for stdlib, which has 81 versions in
        // 4,286 SBOMs (ocidex-nps9.2).
        withVersions(81, 0);
        const { container } = renderAt("/components/overview?name=lodash");

        expect(container.querySelectorAll("tbody tr")).toHaveLength(DEFAULT_PAGE_SIZE);
        expect(container.textContent).toContain("81 versions in 4286 SBOMs · 20 artifacts");
        expect(container.textContent).not.toContain("on this page");
        expect(container.querySelector(".pagination")?.textContent).toContain(`1 / ${Math.ceil(81 / DEFAULT_PAGE_SIZE)}`);
    });

    it("shows each version's own SBOM and artifact counts", () => {
        withVersions(1, 0, 1);
        const { container } = renderAt("/components/overview?name=lodash");

        const cells = container.querySelector("tbody tr")?.textContent ?? "";
        expect(cells).toContain("3 SBOMs");
        expect(cells).toContain("2 artifacts");
    });

    it("keeps the plain header and no controls when everything fits on one page", () => {
        withVersions(3, 0, 3);
        const { container } = renderAt("/components/overview?name=lodash");

        expect(container.querySelector(".pagination")).toBeNull();
        expect(container.textContent).not.toContain("on this page");
    });

    it("lists SBOM occurrences once a version is pinned", () => {
        mockSummaries.mockReturnValue(queryState({}));
        mockVersions.mockReturnValue(
            queryState({
                data: {
                    versions: [row(1), row(2)],
                    pagination: { total: 2, limit: DEFAULT_PAGE_SIZE, offset: 0 },
                    sbomCount: 2,
                },
            }),
        );
        const { container } = renderAt("/components/overview?name=lodash&version=4.17.1");

        expect(container.textContent).toContain("2 artifacts");
    });
});

// ocidex-nps9.24: a bare /components/overview was a dead end.
describe("ComponentOverview without a name", () => {
    it("sends the reader to the components list", async () => {
        mockVersions.mockReturnValue(queryState({}));
        mockSummaries.mockReturnValue(queryState({}));
        mockComponent.mockReturnValue(queryState({}));
        mockVulns.mockReturnValue(queryState({}));
        window.history.replaceState({}, "", "/components/overview");
        render(() => (
            <Router root={(props) => <>{props.children}</>}>
                <Route path="/components/overview" component={ComponentOverview} />
                <Route path="/components" component={() => <p>components list</p>} />
            </Router>
        ));
        await waitFor(() => expect(window.location.pathname).toBe("/components"));
    });
});
