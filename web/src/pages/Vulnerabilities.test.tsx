// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Router } from "@solidjs/router";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";
import { useTopVulnerabilities } from "~/api/queries";
import Vulnerabilities, { fixAgeDays } from "~/pages/Vulnerabilities";
import { useAuth } from "~/context/auth";

vi.mock("~/api/queries", () => ({
    useTopVulnerabilities: vi.fn(),
}));

// Signed out unless a test says otherwise: the pods column is signed-in only.
vi.mock("~/context/auth", () => ({ useAuth: vi.fn(() => ({ user: () => undefined })) }));

// The router is real here, not stubbed. Both filters on this page are URL state
// now, so a stub would let a broken read or write pass: the severity strip and
// the id box are only correct if useSearchParams itself agrees.

// Vitest runs without globals, so the testing library cannot register its own
// afterEach. Without this, a Toolbar left mounted commits its pending debounce
// into the next test's URL.
afterEach(cleanup);

const mockUseTopVulns = vi.mocked(useTopVulnerabilities);

interface QueryParams {
    limit?: number;
    offset?: number;
    q?: string;
    severity?: string;
    sort?: string;
    sortDir?: string;
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
        latestAffectedCount: 1,
        publishedAt: "2024-01-01T00:00:00Z",
    },
];

/**
 * Renders the page and exposes the params the page most recently handed the
 * query hook — the observable proof that a sort went to the server rather than
 * being applied to the rows already on screen.
 */
function renderPage(path = "/vulnerabilities") {
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

    return { ...renderAt(path), params: () => latest() };
}

function renderAt(path: string) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            {[{ path: "/vulnerabilities", component: () => <Vulnerabilities /> }]}
        </Router>
    ));
}

function idInput(container: HTMLElement): HTMLInputElement {
    const el = container.querySelector<HTMLInputElement>('input[type="text"]');
    if (el === null) throw new Error("id filter input not rendered");
    return el;
}

// The severity strip highlighted nothing at all for as long as it existed: its
// markup emitted class names the stylesheet never defined, so all six tabs
// computed identically and the current filter was unreadable (ocidex-ag4q.6).
// The contract is `.filter-chips button.active`, and these assert the rendered DOM
// against it rather than against the strip's internal state.
describe("Vulnerabilities severity filter", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("marks All active before a severity is chosen", () => {
        const { container } = renderPage();
        const active = container.querySelectorAll(".filter-chips button.active");
        expect(active.length).toBe(1);
        expect(active[0].textContent).toBe("All");
    });

    it("moves the highlight to the clicked severity and filters the query", async () => {
        const { container, params } = renderPage();
        expect(params().severity).toBe("");

        // Scoped to the strip: "HIGH" also appears as a severity pill in the
        // rows below.
        const [high] = [...container.querySelectorAll(".filter-chips button")].filter(
            (b) => b.textContent === "HIGH",
        );
        expect(high).toBeDefined();
        fireEvent.click(high);

        // The filter is a URL param now, so the router applies it on the next
        // tick rather than the click itself — the same shape <Toolbar> already
        // has for its debounced fields.
        await waitFor(() => {
            const active = container.querySelectorAll(".filter-chips button.active");
            expect(active.length).toBe(1);
            expect(active[0].textContent).toBe("HIGH");
        });
        expect(params().severity).toBe("HIGH");
    });
});

describe("Vulnerabilities sorting", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("defaults to how long a fix has been out", () => {
        const { params } = renderPage();
        expect(params().sort).toBe("fixAge");
        expect(params().sortDir).toBe("desc");
    });

    // The page is server-paginated: a client-side sort would order only the 25
    // rows on screen and silently misreport the ranking.
    it("re-queries with the clicked column instead of reordering the page", () => {
        const { getByText, params } = renderPage();

        fireEvent.click(getByText("Latest tags still affected"));

        expect(params().sort).toBe("latestAffectedCount");
        expect(params().sortDir).toBe("desc");
        // A new ordering invalidates the current page window.
        expect(params().offset).toBe(0);
    });

    it("toggles direction when the active column is clicked again", () => {
        const { getByText, params } = renderPage();

        fireEvent.click(getByText("CVSS"));
        expect(params().sortDir).toBe("desc");

        fireEvent.click(getByText("CVSS"));
        expect(params().sort).toBe("cvssScore");
        expect(params().sortDir).toBe("asc");
    });

    it("leaves the free-text summary column unsortable", () => {
        const { getByText, params } = renderPage();

        fireEvent.click(getByText("Summary"));

        expect(params().sort).toBe("fixAge");
    });
});

// The id box used to be a submit-on-Enter form that navigated to a detail page,
// so the one question this list answers — "does this CVE touch anything we
// track?" — required leaving the list to find out, and came back with a page
// that renders for *every* advisory whether it affects the corpus or not.
describe("Vulnerabilities id filter", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("reads the id from the query string, into both the box and the query", () => {
        const { container, params } = renderPage("/vulnerabilities?q=CVE-2024-0001");
        expect(idInput(container).value).toBe("CVE-2024-0001");
        expect(params().q).toBe("CVE-2024-0001");
    });

    it("filters as you type rather than on submit", async () => {
        vi.useFakeTimers();
        try {
            const { container } = renderPage();
            const input = idInput(container);
            for (const v of ["G", "GH", "GHS", "GHSA"]) {
                fireEvent.input(input, { target: { value: v } });
            }
            // Nothing committed yet — the pause is the whole point on a list
            // this expensive to re-query.
            expect(window.location.search).toBe("");
            vi.advanceTimersByTime(300);
        } finally {
            vi.useRealTimers();
        }
        await waitFor(() => {
            expect(window.location.search).toBe("?q=GHSA");
        });
    });

    it("keeps severity and id independent in the URL", async () => {
        const { container, params } = renderPage("/vulnerabilities?q=CVE-2024-0001");
        const [high] = [...container.querySelectorAll(".filter-chips button")].filter(
            (b) => b.textContent === "HIGH",
        );
        fireEvent.click(high);
        await waitFor(() => {
            expect(params().severity).toBe("HIGH");
        });
        expect(params().q).toBe("CVE-2024-0001");
        expect(window.location.search).toContain("q=CVE-2024-0001");
        expect(window.location.search).toContain("severity=HIGH");
    });

    it("drops the severity param for All instead of storing an empty one", async () => {
        const { container } = renderPage("/vulnerabilities?severity=HIGH");
        const [all] = [...container.querySelectorAll(".filter-chips button")].filter(
            (b) => b.textContent === "All",
        );
        fireEvent.click(all);
        await waitFor(() => {
            expect(window.location.search).not.toContain("severity");
        });
    });

    // A filtered list that finds nothing is not proof the advisory is fictional
    // — it may simply affect nothing tracked. The empty state has to say so and
    // still offer the direct link the old jump box provided.
    it("offers the direct link when the filter matches nothing", () => {
        mockUseTopVulns.mockImplementation((() => ({
            data: { data: [], pagination: { total: 0, limit: 25, offset: 0 } },
            isFetching: false,
            isError: false,
            error: null,
        })) as unknown as typeof useTopVulnerabilities);
        const { container } = renderAt("/vulnerabilities?q=CVE-9999-0001");
        const link = container.querySelector<HTMLAnchorElement>(
            'a[href="/vulnerabilities/CVE-9999-0001"]',
        );
        expect(link).not.toBeNull();
        expect(container.textContent).toContain("CVE-9999-0001");
    });

    it("offers no such link when nothing is filtered", () => {
        mockUseTopVulns.mockImplementation((() => ({
            data: { data: [], pagination: { total: 0, limit: 25, offset: 0 } },
            isFetching: false,
            isError: false,
            error: null,
        })) as unknown as typeof useTopVulnerabilities);
        const { container } = renderAt("/vulnerabilities");
        expect(container.querySelector(".empty-state a")).toBeNull();
    });
});

describe("Vulnerabilities latest-tag columns", () => {
    const row = {
        id: "CVE-2031-1",
        canonicalId: "CVE-2031-1",
        severity: "HIGH",
        aliases: [],
        affectedSbomCount: 1018,
        affectedPurlCount: 2,
        latestAffectedCount: 3,
        fixAvailableSince: new Date(Date.now() - 12 * 86_400_000).toISOString(),
        runningPods: 7,
    };
    const withRows = () =>
        mockUseTopVulns.mockReturnValue({
            data: { data: [row], pagination: { total: 1, limit: 25, offset: 0 } },
            isFetching: false,
            isError: false,
            error: null,
        } as never);

    afterEach(() => vi.mocked(useAuth).mockReturnValue({ user: () => undefined } as never));

    it("counts latest tags, not every SBOM, and says how long the fix has been out", () => {
        withRows();
        const { container } = renderAt("/vulnerabilities");
        const text = container.textContent;
        expect(text).toContain("Latest tags still affected");
        expect(text).not.toContain("Affected SBOMs");
        expect(text).toContain("12 d");
        expect(text).not.toContain("Running pods");
    });

    it("adds running pods for a signed-in caller", () => {
        withRows();
        vi.mocked(useAuth).mockReturnValue({ user: () => ({ displayName: "x" }) } as never);
        const { container } = renderAt("/vulnerabilities");
        expect(container.textContent).toContain("Running pods");
    });

    it("fixAgeDays floors to whole days and never goes negative", () => {
        const now = Date.parse("2026-11-23T12:00:00Z");
        expect(fixAgeDays("2026-11-20T13:00:00Z", now)).toBe(2);
        expect(fixAgeDays("2026-11-24T00:00:00Z", now)).toBe(0);
    });
});
