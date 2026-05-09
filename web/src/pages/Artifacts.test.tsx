// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import { useArtifacts } from "~/api/queries";
import Artifacts from "~/pages/Artifacts";
import type { JSX } from "solid-js";

vi.mock("~/api/queries", () => ({
    useArtifacts: vi.fn(),
}));

vi.mock("~/api/client", () => ({
    API_BASE_URL: "",
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

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element }) => (
        <a href={props.href}>{props.children}</a>
    ),
}));

const mockUseArtifacts = vi.mocked(useArtifacts);

interface MockQuery {
    isLoading: boolean;
    isError: boolean;
    error: unknown;
    data: { data: ArtifactRow[]; pagination: Pagination } | undefined;
}

interface ArtifactRow {
    id: string;
    name: string;
    type: string;
    sbomCount: number;
    sufficientSbomCount: number;
    group?: string;
}

interface Pagination { total: number; limit: number; offset: number }

function makeQuery(overrides: Partial<MockQuery>): MockQuery {
    return { isLoading: false, isError: false, error: null, data: undefined, ...overrides };
}

function makeArtifact(overrides?: Partial<ArtifactRow>): ArtifactRow {
    return { id: "artifact-uuid-1", name: "myapp", type: "container", sbomCount: 3, sufficientSbomCount: 2, ...overrides };
}

const defaultPagination: Pagination = { total: 1, limit: 50, offset: 0 };

function renderArtifacts() {
    return render(() => <Artifacts />);
}

describe("Artifacts", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("shows loading spinner", () => {
        mockUseArtifacts.mockReturnValue(makeQuery({ isLoading: true }) as never);
        const { getByText } = renderArtifacts();
        expect(getByText("Loading…")).toBeDefined();
    });

    it("shows error message on query failure", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ isError: true, error: new Error("network failure") }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("network failure")).toBeDefined();
    });

    it("shows empty state when no artifacts returned", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: { data: [], pagination: { total: 0, limit: 50, offset: 0 } } }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("No artifacts found")).toBeDefined();
    });

    it("renders artifact rows with links to detail pages", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: { data: [makeArtifact()], pagination: defaultPagination } }) as never
        );
        const { getByRole } = renderArtifacts();
        const link = getByRole("link", { name: /myapp/i });
        expect(link.getAttribute("href")).toBe("/artifacts/artifact-uuid-1");
    });

    it("renders artifact type badge", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: { data: [makeArtifact({ type: "library" })], pagination: defaultPagination } }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("library")).toBeDefined();
    });

    it("renders SBOM count", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({ data: { data: [makeArtifact({ sbomCount: 5 })], pagination: defaultPagination } }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("5 SBOMs")).toBeDefined();
    });

    it("renders display name with group prefix", () => {
        mockUseArtifacts.mockReturnValue(
            makeQuery({
                data: { data: [makeArtifact({ name: "mylib", group: "org.example" })], pagination: defaultPagination },
            }) as never
        );
        const { getByText } = renderArtifacts();
        expect(getByText("org.example/mylib")).toBeDefined();
    });
});
