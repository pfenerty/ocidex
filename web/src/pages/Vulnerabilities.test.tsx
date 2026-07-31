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
