// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";
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

// vitest runs without globals here, so @solidjs/testing-library cannot register
// its own afterEach. Without this a toolbar left mounted by one test commits its
// pending debounce into the next test's URL.
afterEach(cleanup);

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

// The three filters were undebounced local signals before ocidex-ag4q.29: a
// request per keystroke against the slowest endpoint in the app, and a filtered
// list that could not be linked to or reloaded.
describe("Components filters live in the URL", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockDistinct.mockReturnValue(
            queryState({ data: { data: [], pagination: { total: 0, limit: 20, offset: 0 } } }),
        );
        mockPurlTypes.mockReturnValue(queryState({ data: { types: ["npm", "golang"] } }));
    });

    const textInputs = (c: HTMLElement) =>
        [...c.querySelectorAll<HTMLInputElement>('input[type="text"]')];

    it("seeds all three from the query string, into the boxes and the query", () => {
        const { container } = renderAt(
            "/components?name=lodash&group=org.example&purlType=npm",
        );

        expect(textInputs(container).map((i) => i.value)).toEqual(["lodash", "org.example"]);
        const select = container.querySelector("select");
        expect(select?.value).toBe("npm");

        const args = mockDistinct.mock.calls[0][0]();
        expect(args.name).toBe("lodash");
        expect(args.group).toBe("org.example");
        expect(args.purl_type).toBe("npm");
    });

    it("waits for a pause before querying, rather than firing per character", async () => {
        const { container } = renderAt("/components");
        const [name] = textInputs(container);

        fireEvent.input(name, { target: { value: "lod" } });
        // The box has it; the URL — and so the query — does not, yet.
        expect(name.value).toBe("lod");
        expect(window.location.search).toBe("");

        await waitFor(() => {
            expect(window.location.search).toBe("?name=lod");
        });
        expect(mockDistinct.mock.calls[0][0]().name).toBe("lod");
    });

    // `purlType` sits beside the `purl` param that switches this page over to
    // the occurrence list entirely (ADR-042 R6). A prefix match between the two
    // would send a package-type filter to the wrong view.
    it("does not confuse purlType with the ?purl= occurrence switch", () => {
        renderAt("/components?purlType=npm");

        expect(mockDistinct).toHaveBeenCalled();
        expect(mockByPurl).not.toHaveBeenCalled();
    });

    it("clears every filter at once and returns to the unfiltered list", async () => {
        const { container, getByRole } = renderAt(
            "/components?name=lodash&group=org.example&purlType=npm",
        );

        getByRole("button", { name: "Clear" }).click();

        await waitFor(() => {
            expect(window.location.search).toBe("");
        });
        expect(textInputs(container).map((i) => i.value)).toEqual(["", ""]);
    });
});
