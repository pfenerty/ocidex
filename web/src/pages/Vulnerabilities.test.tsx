// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { useTopVulnerabilities } from "~/api/queries";
import Vulnerabilities from "~/pages/Vulnerabilities";
import type { JSX } from "solid-js";

vi.mock("~/api/queries", () => ({
    useTopVulnerabilities: vi.fn(),
}));

vi.mock("@solidjs/router", () => ({
    useNavigate: () => vi.fn(),
    A: (props: { href: string; children?: JSX.Element }) => (
        <a href={props.href}>{props.children}</a>
    ),
}));

const mockUseTopVulns = vi.mocked(useTopVulnerabilities);

interface QueryParams {
    limit?: number;
    offset?: number;
    severity?: string;
    sort?: string;
    sort_dir?: string;
}

const rows = [
    {
        id: "CVE-2024-0001",
        canonicalId: "CVE-2024-0001",
        severity: "HIGH",
        cvssScore: 7.5,
        summary: "something bad",
        affectedSbomCount: 3,
        affectedPurlCount: 2,
        publishedAt: "2024-01-01T00:00:00Z",
    },
];

/**
 * Renders the page and exposes the params the page most recently handed the
 * query hook — the observable proof that a sort went to the server rather than
 * being applied to the rows already on screen.
 */
function renderPage() {
    // Hold the accessor rather than a snapshot: it reads the page's signals, so
    // calling it after an interaction reports what the real hook would query.
    let latest: () => QueryParams = () => ({});
    mockUseTopVulns.mockImplementation(((params: () => QueryParams) => {
        latest = params;
        return {
            data: { data: rows, pagination: { total: 1, limit: 25, offset: 0 } },
            isFetching: false,
            isError: false,
            error: null,
        };
    }) as unknown as typeof useTopVulnerabilities);

    const rendered = render(() => <Vulnerabilities />);
    return { ...rendered, params: () => latest() };
}

// The severity strip highlighted nothing at all for as long as it existed: its
// markup emitted class names the stylesheet never defined, so all six tabs
// computed identically and the current filter was unreadable (ocidex-ag4q.6).
// The contract is `.tab-bar button.active`, and these assert the rendered DOM
// against it rather than against the strip's internal state.
describe("Vulnerabilities severity filter", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("marks All active before a severity is chosen", () => {
        const { container } = renderPage();
        const active = container.querySelectorAll(".tab-bar button.active");
        expect(active.length).toBe(1);
        expect(active[0].textContent).toBe("All");
    });

    it("moves the highlight to the clicked severity and filters the query", () => {
        const { container, params } = renderPage();
        expect(params().severity).toBe("");

        // Scoped to the strip: "HIGH" also appears as a severity pill in the
        // rows below.
        const [high] = [...container.querySelectorAll(".tab-bar button")].filter(
            (b) => b.textContent === "HIGH",
        );
        expect(high).toBeDefined();
        fireEvent.click(high);

        const active = container.querySelectorAll(".tab-bar button.active");
        expect(active.length).toBe(1);
        expect(active[0].textContent).toBe("HIGH");
        expect(params().severity).toBe("HIGH");
    });
});

describe("Vulnerabilities sorting", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("defaults to the severity ranking", () => {
        const { params } = renderPage();
        expect(params().sort).toBe("severity");
        expect(params().sort_dir).toBe("desc");
    });

    // The page is server-paginated: a client-side sort would order only the 25
    // rows on screen and silently misreport the ranking.
    it("re-queries with the clicked column instead of reordering the page", () => {
        const { getByText, params } = renderPage();

        fireEvent.click(getByText("Affected SBOMs"));

        expect(params().sort).toBe("affected_sbom_count");
        expect(params().sort_dir).toBe("desc");
        // A new ordering invalidates the current page window.
        expect(params().offset).toBe(0);
    });

    it("toggles direction when the active column is clicked again", () => {
        const { getByText, params } = renderPage();

        fireEvent.click(getByText("CVSS"));
        expect(params().sort_dir).toBe("desc");

        fireEvent.click(getByText("CVSS"));
        expect(params().sort).toBe("cvss_score");
        expect(params().sort_dir).toBe("asc");
    });

    it("leaves the free-text summary column unsortable", () => {
        const { getByText, params } = renderPage();

        fireEvent.click(getByText("Summary"));

        expect(params().sort).toBe("severity");
    });
});
