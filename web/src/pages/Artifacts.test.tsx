// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import { useArtifactsInfinite } from "~/api/queries";
import Artifacts from "~/pages/Artifacts";
import type { JSX } from "solid-js";

vi.mock("~/api/queries", () => ({
    useArtifactsInfinite: vi.fn(),
}));

vi.mock("~/api/client", () => ({
    API_BASE_URL: "",
    DEFAULT_PAGE_SIZE: 20,
    client: {},
    APIClientError: class extends Error {
        status: number;
        body: unknown;
        constructor(status: number, body: unknown) {
            super(`HTTP ${status}`);
            this.status = status;
            this.body = body;
        }
    },
    unwrap: vi.fn(),
}));

// The type filter reads and writes the URL, so the router stub has to carry
// search params rather than just render links.
const router = vi.hoisted(() => {
    // Annotated, not asserted: the eslint fixer strips an `as` here and the
    // params object collapses to `{}`, which tsc then refuses to index.
    const searchParams: Record<string, string | undefined> = {};
    return { searchParams, setSearchParams: vi.fn() };
});

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element }) => (
        <a href={props.href}>{props.children}</a>
    ),
    useSearchParams: () => [router.searchParams, router.setSearchParams] as const,
}));

const mockUseArtifacts = vi.mocked(useArtifactsInfinite);

interface ArtifactRow {
    id: string;
    name: string;
    type: string;
    sbomCount: number;
    sufficientSbomCount: number;
    group?: string;
}

interface InfiniteQuery {
    isLoading: boolean;
    isError: boolean;
    error: unknown;
    data: { pages: { data: ArtifactRow[] }[] } | undefined;
    hasNextPage: boolean;
    isFetchingNextPage: boolean;
    fetchNextPage: () => void;
}

function makeQuery(overrides: Partial<InfiniteQuery>): InfiniteQuery {
    return {
        isLoading: false,
        isError: false,
        error: null,
        data: undefined,
        hasNextPage: false,
        isFetchingNextPage: false,
        fetchNextPage: vi.fn(),
        ...overrides,
    };
}

function makeArtifact(overrides?: Partial<ArtifactRow>): ArtifactRow {
    return { id: "artifact-uuid-1", name: "myapp", type: "container", sbomCount: 3, sufficientSbomCount: 2, ...overrides };
}

// page wraps artifact rows in the single-page shape returned by the infinite query.
function page(rows: ArtifactRow[]): { pages: { data: ArtifactRow[] }[] } {
    return { pages: [{ data: rows }] };
}

function renderArtifacts() {
    return render(() => <Artifacts />);
}

describe("Artifacts", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        for (const k of Object.keys(router.searchParams)) delete router.searchParams[k];
    });

    it("shows a skeleton table while loading", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ isLoading: true }) as never);
        const { container, getByText } = renderArtifacts();
        // Real headers render immediately; body is shimmer, not a spinner.
        expect(getByText("Artifact")).toBeDefined();
        expect(container.querySelector(".skeleton")).not.toBeNull();
        expect(container.querySelector(".spinner")).toBeNull();
    });

    it("shows error message on query failure", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ isError: true, error: new Error("network failure") }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("network failure")).toBeDefined();
    });

    it("shows empty state when no artifacts returned", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([]) }) as never);
        const { getByText } = renderArtifacts();
        expect(getByText("No artifacts found")).toBeDefined();
    });

    it("renders artifact rows with links to detail pages", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([makeArtifact()]) }) as never);
        const { getByRole } = renderArtifacts();
        const link = getByRole("link", { name: /myapp/i });
        expect(link.getAttribute("href")).toBe("/artifacts/artifact-uuid-1");
    });

    it("renders artifact type badge", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: page([makeArtifact({ type: "library" })]) }) as never
        );
        const { container } = renderArtifacts();
        // The type filter renders an <option> with the same text, so scope the
        // assertion to the row's badge — otherwise it passes on the filter and
        // says nothing about whether the row rendered.
        const badges = Array.from(container.querySelectorAll("td span.badge"));
        expect(badges.some((b) => b.textContent === "library")).toBe(true);
    });

    it("renders SBOM count", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: page([makeArtifact({ sbomCount: 5 })]) }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("5 SBOMs")).toBeDefined();
    });

    it("renders display name with group prefix", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: page([makeArtifact({ name: "mylib", group: "org.example" })]) }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("org.example/mylib")).toBeDefined();
    });

    // --- grouping (ocidex-rj4.5) --------------------------------------------
    // The list is no longer container-only, so the heading has to follow the
    // identity each type actually has instead of parsing every name as an OCI
    // repository path.

    function headings(container: HTMLElement): string[] {
        return [...container.querySelectorAll("tr.group-header-row td")].map((td) =>
            // Strip the trailing count badge so assertions read as the label.
            td.textContent.replace(/\s*\d+\s*$/, "").trim()
        );
    }

    it("groups containers by their registry path", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: page([
                    makeArtifact({ id: "a", name: "ghcr.io/pfenerty/ocidex-api" }),
                    makeArtifact({ id: "b", name: "docker.io/library/postgres" }),
                ]),
            }) as never
        );
        const { container } = renderArtifacts();
        expect(headings(container)).toEqual(["ghcr.io/pfenerty", "docker.io/library"]);
    });

    it("groups a non-container by its package group, not by an OCI path parse", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: page([
                    makeArtifact({ id: "a", name: "ghcr.io/pfenerty/ocidex-api" }),
                    makeArtifact({ id: "b", name: "mylib", type: "library", group: "org.example" }),
                ]),
            }) as never
        );
        const { container } = renderArtifacts();
        const hs = headings(container);
        expect(hs).toContain("org.example");
        // The old behaviour bucketed a slash-free name under itself, producing a
        // heading that just repeated the single row beneath it.
        expect(hs).not.toContain("mylib");
    });

    it("falls back to the type when a non-container has no package group", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: page([
                    makeArtifact({ id: "a", name: "ghcr.io/pfenerty/ocidex-api" }),
                    makeArtifact({ id: "b", name: "ocidex-cli", type: "application" }),
                ]),
            }) as never
        );
        const { container } = renderArtifacts();
        const hs = headings(container);
        expect(hs).toContain("application");
        expect(hs).not.toContain("ocidex-cli");
    });

    it("omits group headings entirely when there is only one group", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: page([
                    makeArtifact({ id: "a", name: "ghcr.io/pfenerty/ocidex-api" }),
                    makeArtifact({ id: "b", name: "ghcr.io/pfenerty/ocidex-web" }),
                ]),
            }) as never
        );
        const { container } = renderArtifacts();
        expect(container.querySelector("tr.group-header-row")).toBeNull();
    });

    // --- URL-driven type filter (ocidex-l1e0) --------------------------------
    // Home's artifact-type chips link straight here, so the filter has to come
    // from the URL rather than from component-local state.

    function typeSelect(container: HTMLElement): HTMLSelectElement {
        const el = container.querySelector("select");
        if (el === null) throw new Error("type filter select not rendered");
        return el;
    }

    it("initialises the type filter from the URL", () => {
        router.searchParams.type = "library";
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([]) }) as never);

        const { container } = renderArtifacts();

        expect(typeSelect(container).value).toBe("library");
        expect(mockUseArtifacts.mock.calls[0][0]().type).toBe("library");
    });

    it("writes the chosen type to the URL", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([]) }) as never);
        const { container } = renderArtifacts();

        const select = typeSelect(container);
        select.value = "application";
        select.dispatchEvent(new Event("change", { bubbles: true }));

        expect(router.setSearchParams).toHaveBeenCalledWith({ type: "application" });
    });

    // "All types" has to clear the param, not write type=""; a stray empty
    // param would survive in shared links and read as a filter that is set.
    it("clears the type param when All types is selected", () => {
        router.searchParams.type = "library";
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([]) }) as never);
        const { container } = renderArtifacts();

        const select = typeSelect(container);
        select.value = "";
        select.dispatchEvent(new Event("change", { bubbles: true }));

        expect(router.setSearchParams).toHaveBeenCalledWith({ type: undefined });
    });
});
