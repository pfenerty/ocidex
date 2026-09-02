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

function nameInput(container: HTMLElement): HTMLInputElement {
    const el = container.querySelector<HTMLInputElement>('input[type="text"]');
    if (el === null) throw new Error("name filter input not rendered");
    return el;
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
            isFetching: false,
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

// Adopting <Toolbar> (ocidex-ag4q.28) moved the name filter out of a
// component-local signal and into the query string, alongside the type that was
// already there. Against the real router these assert the thing the local
// signal could not do: a filtered list that survives a reload and can be sent
// to someone else.
describe("Artifacts name filter against the real router", () => {
    const idleQuery = () => ({
        isLoading: false,
        isFetching: false,
        isError: false,
        error: null,
        data: { pages: [{ data: [] }] },
        hasNextPage: false,
        isFetchingNextPage: false,
        fetchNextPage: vi.fn(),
    });

    beforeEach(() => {
        vi.clearAllMocks();
        mockUseArtifacts.mockReturnValue(idleQuery() as never);
    });

    it("reads the name from the query string, into both the box and the query", () => {
        const { container } = renderAt("/artifacts?name=postgres");

        expect(nameInput(container).value).toBe("postgres");
        expect(mockUseArtifacts.mock.calls[0][0]().name).toBe("postgres");
    });

    it("debounces a keystroke rather than writing the URL per character", async () => {
        vi.useFakeTimers();
        try {
            const { container } = renderAt("/artifacts");
            const input = nameInput(container);

            input.value = "pg";
            input.dispatchEvent(new Event("input", { bubbles: true }));
            // The box shows the character immediately; only the URL waits.
            expect(input.value).toBe("pg");
            expect(window.location.search).toBe("");

            vi.advanceTimersByTime(300);
        } finally {
            vi.useRealTimers();
        }

        await waitFor(() => {
            expect(window.location.search).toBe("?name=pg");
        });
        expect(mockUseArtifacts.mock.calls[0][0]().name).toBe("pg");
    });

    // The list is unconditionally complete since ocidex-7gf7.8 removed the
    // "Show all" box. `sufficient` stays in the request and stays false: the
    // server's own default is true, so omitting it would restore exactly the
    // hiding the box used to do, silently and with no control to undo it.
    it("asks for every artifact, with no way for the URL to narrow it", () => {
        renderAt("/artifacts?all=1");
        expect(mockUseArtifacts.mock.calls[0][0]().sufficient).toBe(false);

        vi.clearAllMocks();
        mockUseArtifacts.mockReturnValue(idleQuery() as never);
        renderAt("/artifacts");
        expect(mockUseArtifacts.mock.calls[0][0]().sufficient).toBe(false);
    });

    it("clears every filter param at once, not just the one last touched", async () => {
        const { getByRole } = renderAt("/artifacts?name=postgres&type=library");

        getByRole("button", { name: "Clear" }).click();

        await waitFor(() => {
            expect(window.location.search).toBe("");
        });
    });
});
