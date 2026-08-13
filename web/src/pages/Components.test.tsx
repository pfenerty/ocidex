// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import {
    useDistinctComponents,
    useComponentPurlTypes,
    useComponentsByPurl,
} from "~/api/queries";
import Components from "~/pages/Components";

vi.mock("~/api/queries", () => ({
    useDistinctComponents: vi.fn(),
    useComponentPurlTypes: vi.fn(),
    useComponentsByPurl: vi.fn(),
}));

const mockDistinct = vi.mocked(useDistinctComponents);
const mockPurlTypes = vi.mocked(useComponentPurlTypes);
const mockByPurl = vi.mocked(useComponentsByPurl);

function queryState(over: Record<string, unknown>) {
    return { isLoading: false, isFetching: false, isError: false, error: null, data: undefined, ...over } as never;
}

function renderAt(path: string) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            <Route path="/components" component={Components} />
        </Router>
    ));
}

describe("Components ?purl= filter", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockDistinct.mockReturnValue(
            queryState({ data: { data: [], pagination: { total: 0, limit: 20, offset: 0 } } }),
        );
        mockPurlTypes.mockReturnValue(queryState({ data: [] }));
        mockByPurl.mockReturnValue(
            queryState({
                data: {
                    data: [
                        { id: "c1", sbomId: "sbom-1", name: "lodash", version: "4.17.21", type: "library", isDirect: true },
                    ],
                    pagination: { total: 1, limit: 20, offset: 0 },
                },
            }),
        );
    });

    it("renders the occurrence list for a purl link", () => {
        const { getByText, container } = renderAt(
            `/components?purl=${encodeURIComponent("pkg:npm/lodash@4.17.21")}`,
        );

        expect(getByText("Component occurrences")).toBeTruthy();
        expect(getByText("pkg:npm/lodash@4.17.21")).toBeTruthy();
        expect(mockByPurl.mock.calls[0][0]().purl).toBe("pkg:npm/lodash@4.17.21");
        // No component detail route exists (ADR-042 R6) — the row links to the SBOM.
        const hrefs = [...container.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(hrefs).toContain("/sboms/sbom-1");
    });

    it("browses distinct components when no purl is given", () => {
        renderAt("/components");

        expect(mockDistinct).toHaveBeenCalled();
        expect(mockByPurl).not.toHaveBeenCalled();
    });
});
