// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Router } from "@solidjs/router";
import { render, waitFor } from "@solidjs/testing-library";
import { useArtifactsInfinite } from "~/api/queries";
import Artifacts from "~/pages/Artifacts";

vi.mock("~/api/queries", () => ({
    useArtifactsInfinite: vi.fn(),
}));

vi.mock("~/api/client", () => ({
    API_BASE_URL: "",
    DEFAULT_PAGE_SIZE: 20,
    client: {},
    unwrap: vi.fn(),
}));

const mockUseArtifacts = vi.mocked(useArtifactsInfinite);

// Artifacts.test.tsx stubs @solidjs/router, so it proves the component's side of
// the contract but nothing about useSearchParams itself. These cases mount the
// real router: the type filter used to be a plain signal, and swapping it for
// URL state is only correct if reading, writing and clearing the param all
// behave against the actual implementation.
function renderAt(path: string) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            {[{ path: "/artifacts", component: () => <Artifacts /> }]}
        </Router>
    ));
}

function typeSelect(container: HTMLElement): HTMLSelectElement {
    const el = container.querySelector("select");
    if (el === null) throw new Error("type filter select not rendered");
    return el;
}

describe("Artifacts type filter against the real router", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockUseArtifacts.mockReturnValue({
            isLoading: false,
            isError: false,
            error: null,
            data: { pages: [{ data: [] }] },
            hasNextPage: false,
            isFetchingNextPage: false,
            fetchNextPage: vi.fn(),
        } as never);
    });

    it("reads the type from the query string", () => {
        const { container } = renderAt("/artifacts?type=library");

        expect(typeSelect(container).value).toBe("library");
        expect(mockUseArtifacts.mock.calls[0][0]().type).toBe("library");
    });

    it("pushes the chosen type into the URL and re-queries", async () => {
        const { container } = renderAt("/artifacts");
        const select = typeSelect(container);

        select.value = "application";
        select.dispatchEvent(new Event("change", { bubbles: true }));

        await waitFor(() => {
            expect(window.location.search).toBe("?type=application");
        });
        // The query params are an accessor, so the new type has to be visible
        // through the same one the component already handed to the hook.
        expect(mockUseArtifacts.mock.calls[0][0]().type).toBe("application");
    });

    it("drops the param entirely when All types is chosen", async () => {
        const { container } = renderAt("/artifacts?type=library");
        const select = typeSelect(container);

        select.value = "";
        select.dispatchEvent(new Event("change", { bubbles: true }));

        await waitFor(() => {
            expect(window.location.search).toBe("");
        });
        expect(mockUseArtifacts.mock.calls[0][0]().type).toBe("");
    });
});
