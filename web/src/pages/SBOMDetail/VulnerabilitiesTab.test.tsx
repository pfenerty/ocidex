// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import type { JSX } from "solid-js";
import { render, cleanup } from "@solidjs/testing-library";
import type { SBOMVulnEntry, VulnSummary } from "~/api/client";
import { useSBOMVulns } from "~/api/queries";
import { VulnerabilitiesTab } from "./VulnerabilitiesTab";

vi.mock("~/api/queries", () => ({ useSBOMVulns: vi.fn() }));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

const mockVulns = vi.mocked(useSBOMVulns);

/** The params the tab last asked the API for. */
let lastParams: Record<string, unknown> | undefined;

type VulnQuery = ReturnType<typeof useSBOMVulns>;

function stubQuery(rows: SBOMVulnEntry[]): void {
    mockVulns.mockImplementation((_id, params) => {
        lastParams = params?.() as Record<string, unknown> | undefined;
        return {
            data: {
                data: rows,
                pagination: { total: rows.length, limit: 50, offset: 0 },
            },
            isFetching: false,
            isError: false,
            error: null,
        } as unknown as VulnQuery;
    });
}

const summary = (over: Partial<VulnSummary>): VulnSummary => ({
    critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0, ...over,
});

const vuln = (over: Partial<SBOMVulnEntry>): SBOMVulnEntry => ({
    id: "GO-2026-1",
    canonicalId: "CVE-2026-1",
    severity: "CRITICAL",
    affectedPackageCount: 1,
    affectedPackages: [{ purl: "pkg:deb/ubuntu/apt@2.7", name: "apt", matchedViaSource: false }],
    ...over,
});

const expandedKeys = new Set<string>();

type TabProps = Parameters<typeof VulnerabilitiesTab>[0];

/* Props are built as one object rather than spread over JSX defaults: Solid's
   mergeProps drops undefined values from a spread, so an override of
   `summary: undefined` — the never-scanned case — would silently not apply. */
function renderTab(over: Partial<TabProps> = {}) {
    const props: TabProps = {
        sbomId: "s1",
        summary: summary({ critical: 1, total: 1 }),
        severity: undefined,
        sortBy: "severity",
        sortDir: "desc",
        offset: 0,
        expanded: {
            has: (k) => expandedKeys.has(k),
            toggle: (k) => (expandedKeys.has(k) ? expandedKeys.delete(k) : expandedKeys.add(k)),
        },
        onSeverityChange: () => undefined,
        onSort: () => undefined,
        onPageChange: () => undefined,
        ...over,
    };
    return render(() => <VulnerabilitiesTab {...props} />);
}

beforeEach(() => {
    lastParams = undefined;
    expandedKeys.clear();
    stubQuery([vuln({})]);
});
afterEach(() => {
    cleanup();
    vi.clearAllMocks();
});

describe("SBOM VulnerabilitiesTab", () => {
    it("asks the API for the caller's severity, sort and page", () => {
        renderTab({ severity: "HIGH", sortBy: "cvss_score", sortDir: "asc", offset: 50 });
        expect(lastParams).toMatchObject({
            severity: "HIGH",
            sort: "cvss_score",
            dir: "asc",
            offset: 50,
        });
    });

    it("omits severity entirely rather than sending an empty filter", () => {
        renderTab({ severity: undefined });
        expect(lastParams).not.toHaveProperty("severity");
    });

    it("labels a source-package match as inherited, never as a direct hit", () => {
        // A finding published against the source package is a weaker claim than
        // one published against this binary. Dropping the label would silently
        // promote it.
        expandedKeys.add("CVE-2026-1");
        stubQuery([
            vuln({
                affectedPackageCount: 1,
                affectedPackages: [
                    {
                        purl: "pkg:deb/ubuntu/adduser@3.118",
                        name: "adduser",
                        matchedViaSource: true,
                    },
                ],
            }),
        ]);
        const { container } = renderTab();
        expect(container.querySelector(".affected-packages")?.textContent).toContain("via source");
    });

    // The packages a finding lands on arrive inline on the row and used to sit
    // behind a click anyway, so learning what a page of findings touched cost
    // one interaction per row (ocidex-7gf7.9).
    describe("affected packages", () => {
        const pkgs = (n: number) =>
            Array.from({ length: n }, (_, i) => ({
                purl: `pkg:deb/ubuntu/p${i}@1.0`,
                name: `p${i}`,
                matchedViaSource: false,
            }));

        it("names them without waiting for a click", () => {
            stubQuery([vuln({ affectedPackageCount: 2, affectedPackages: pkgs(2) })]);
            const { container } = renderTab();
            const list = container.querySelector(".affected-packages");
            expect(list?.textContent).toContain("p0");
            expect(list?.textContent).toContain("p1");
            expect(container.querySelector(".affected-more")).toBeNull();
        });

        it("shows the first three and offers the rest by count", () => {
            stubQuery([vuln({ affectedPackageCount: 7, affectedPackages: pkgs(7) })]);
            const { container } = renderTab();
            expect(container.querySelectorAll(".affected-packages li")).toHaveLength(3);
            expect(container.querySelector(".affected-more")?.textContent).toBe("+4 more");
        });

        it("shows every one once expanded", () => {
            expandedKeys.add("CVE-2026-1");
            stubQuery([vuln({ affectedPackageCount: 7, affectedPackages: pkgs(7) })]);
            const { container } = renderTab();
            expect(container.querySelectorAll(".affected-packages li")).toHaveLength(7);
            expect(container.querySelector(".affected-more")?.textContent).toBe("Show fewer");
        });

        it("reads as nothing, not as an empty list, when there are none", () => {
            stubQuery([vuln({ affectedPackageCount: 0, affectedPackages: [] })]);
            const { container } = renderTab();
            expect(container.querySelector(".affected-packages")).toBeNull();
        });
    });

    it("keeps never-scanned and clean apart in the empty state", () => {
        // ADR-044's rule for unmatched workloads applies here too: unknown
        // exposure must never render as zero exposure.
        stubQuery([]);
        const notScanned = renderTab({ summary: undefined }).container.textContent;
        expect(notScanned).toContain("Not scanned");
        cleanup();

        const clean = renderTab({ summary: summary({}) }).container.textContent;
        expect(clean).toContain("No known vulnerabilities");
        expect(clean).not.toContain("Not scanned");
    });
});
