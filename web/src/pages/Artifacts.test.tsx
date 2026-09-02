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

interface VulnSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
    total: number;
}

interface ArtifactRow {
    id: string;
    name: string;
    type: string;
    sbomCount: number;
    sufficientSbomCount: number;
    group?: string;
    vulns?: VulnSummary;
}

interface InfiniteQuery {
    isLoading: boolean;
    isFetching: boolean;
    isError: boolean;
    error: unknown;
    data: { pages: { data: ArtifactRow[] }[] } | undefined;
    hasNextPage: boolean;
    isFetchingNextPage: boolean;
    fetchNextPage: () => void;
}

function makeQuery(overrides: Partial<InfiniteQuery>): InfiniteQuery {
    const q: InfiniteQuery = {
        isLoading: false,
        isFetching: false,
        isError: false,
        error: null,
        data: undefined,
        hasNextPage: false,
        isFetchingNextPage: false,
        fetchNextPage: vi.fn(),
        ...overrides,
    };
    // TanStack never reports isLoading without isFetching. DataTable tells
    // first load from refetch by pairing isFetching with whether rows exist, so
    // a mock that drops isFetching silently exercises a state the app cannot be
    // in — and reports "empty" where the real page shows shimmer.
    return { ...q, isFetching: overrides.isFetching ?? q.isLoading };
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

// The bug this guards is the one ADR-044 names: an artifact nobody has scanned
// must never render as a clean zero, and VulnCountBadges' own em-dash fallback
// for an all-zero summary reads exactly like one.
describe("Artifacts severity column", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        for (const k of Object.keys(router.searchParams)) delete router.searchParams[k];
    });

    it("says 'not scanned' when no summary is present", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([makeArtifact()]) }) as never);
        const { getByText } = renderArtifacts();
        expect(getByText("not scanned")).toBeDefined();
    });

    it("renders per-severity counts when a summary is present", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: page([
                    makeArtifact({ vulns: { critical: 2, high: 3, medium: 0, low: 1, unknown: 0, total: 6 } }),
                ]),
            }) as never
        );
        const { container, queryByText } = renderArtifacts();
        expect(queryByText("not scanned")).toBeNull();
        const chip = container.querySelector(".vuln-chip");
        expect(chip?.textContent.replace(/\s+/g, "")).toBe("23010");
    });

    // The two count columns sit side by side and are scoped opposite ways: the
    // vulnerability rollup follows the latest version (ocidex-7gf7.2) because a
    // finding only an old release carries has been superseded, while signing is
    // the worst rung across every SBOM (ocidex-7gf7.3) because a failure
    // anywhere is not cancelled by a sibling that passed. Neither said so, and
    // read together they implied a scope they did not share (ocidex-7gf7.7).
    it("states the scope of the vulnerability and signing columns", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([makeArtifact()]) }) as never);
        const { container } = renderArtifacts();
        const scopes = [...container.querySelectorAll("th .col-scope")].map(
            (s) => s.textContent.trim(),
        );
        expect(scopes).toContain("latest version");
        expect(scopes).toContain("any SBOM");
    });

    it("writes the sort to the URL instead of reordering in place", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ data: page([makeArtifact()]) }) as never);
        const { getByText } = renderArtifacts();

        getByText("Vulnerabilities").click();

        // Server-side: the list is paged, so a client-side sort would only
        // reorder the rows already fetched.
        expect(router.setSearchParams).toHaveBeenCalledWith({ sort: "severity", dir: "desc" });
    });

    // Grouping re-collects rows by name, which would undo the ordering the
    // server just applied, so the two cannot both be on.
    it("drops group headings while sorted by severity", () => {
        router.searchParams.sort = "severity";
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: page([
                    makeArtifact({ id: "a", name: "ghcr.io/one/app" }),
                    makeArtifact({ id: "b", name: "docker.io/two/app" }),
                ]),
            }) as never
        );
        const { container } = renderArtifacts();
        expect(container.querySelectorAll("tr.group-header-row").length).toBe(0);
        expect(mockUseArtifacts.mock.calls[0][0]().sort).toBe("severity");
    });
});
