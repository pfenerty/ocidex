// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import type { JSX } from "solid-js";
import { render, cleanup } from "@solidjs/testing-library";
import type { ArtifactVulnEntry, VulnSummary } from "~/api/client";
import { useArtifactVulns } from "~/api/queries";
import { VulnerabilitiesTab } from "./VulnerabilitiesTab";

vi.mock("~/api/queries", () => ({ useArtifactVulns: vi.fn() }));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

const mockVulns = vi.mocked(useArtifactVulns);

/** The params the tab last asked the API for. */
let lastParams: Record<string, unknown> | undefined;

type VulnQuery = ReturnType<typeof useArtifactVulns>;

function stubQuery(rows: ArtifactVulnEntry[]): void {
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

const vuln = (over: Partial<ArtifactVulnEntry>): ArtifactVulnEntry => ({
    id: "GO-2026-1",
    canonicalId: "CVE-2026-1",
    severity: "CRITICAL",
    affectedPackageCount: 1,
    affectedVersionCount: 1,
    affectedVersions: [
        { version: "1.2.3", sbomId: "sbom-1", affectedPackageCount: 1, packageNames: ["apt"] },
    ],
    ...over,
});

const expandedKeys = new Set<string>();

type TabProps = Parameters<typeof VulnerabilitiesTab>[0];

/* Props are built as one object rather than spread over JSX defaults: Solid's
   mergeProps drops undefined values from a spread, so an override of
   `summary: undefined` — the never-scanned case — would silently not apply. */
function renderTab(over: Partial<TabProps> = {}) {
    const props: TabProps = {
        artifactId: "a1",
        summary: summary({ critical: 1, total: 1 }),
        severity: undefined,
        vuln: undefined,
        sortBy: "severity",
        sortDir: "desc",
        offset: 0,
        expanded: {
            has: (k) => expandedKeys.has(k),
            toggle: (k) => (expandedKeys.has(k) ? expandedKeys.delete(k) : expandedKeys.add(k)),
        },
        onSeverityChange: () => undefined,
        onClearVuln: () => undefined,
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

describe("Artifact VulnerabilitiesTab", () => {
    it("asks the API for the caller's severity, advisory filter, sort and page", () => {
        renderTab({ severity: "HIGH", vuln: "CVE-2026-1", sortBy: "cvss_score", sortDir: "asc", offset: 50 });
        expect(lastParams).toMatchObject({
            severity: "HIGH",
            vuln: "CVE-2026-1",
            sort: "cvss_score",
            dir: "asc",
            offset: 50,
        });
    });

    it("omits severity and vuln entirely rather than sending empty filters", () => {
        renderTab({ severity: undefined, vuln: undefined });
        expect(lastParams).not.toHaveProperty("severity");
        expect(lastParams).not.toHaveProperty("vuln");
    });

    it("expands a row into versions that link to the SBOM carrying each", () => {
        // The count alone is the dead end this tab exists to fix: "2 versions"
        // without naming them leaves the reader exactly where /vulnerabilities
        // left them.
        expandedKeys.add("CVE-2026-1");
        stubQuery([
            vuln({
                affectedVersionCount: 2,
                affectedVersions: [
                    { version: "1.2.3", sbomId: "sbom-1", affectedPackageCount: 1, packageNames: ["apt"] },
                    { version: "1.3.0", sbomId: "sbom-2", affectedPackageCount: 2, packageNames: ["apt", "zlib"] },
                ],
            }),
        ]);
        const { container } = renderTab();
        const links = [...container.querySelectorAll(".affected-versions a")];
        expect(links.map((a) => a.getAttribute("href"))).toEqual([
            "/sboms/sbom-1?tab=vulns&vuln=CVE-2026-1",
            "/sboms/sbom-2?tab=vulns&vuln=CVE-2026-1",
        ]);
        expect(container.querySelector(".affected-versions")?.textContent).toContain("1.3.0");
    });

    it("says a pre-filtered list is filtered, and offers a way out", () => {
        // A ?vuln= list that looks unfiltered reads as "this is everything the
        // artifact has", which is the opposite of true.
        const { container } = renderTab({ vuln: "CVE-2026-1" });
        expect(container.textContent).toContain("CVE-2026-1");
        expect(container.textContent).toContain("Show all vulnerabilities");
    });

    it("distinguishes not-affected-by-this-advisory from clean and from never scanned", () => {
        // ADR-044's rule for unmatched workloads applies here too: unknown
        // exposure must never render as zero exposure — and an empty filtered
        // list is a claim about one advisory, not about the artifact.
        stubQuery([]);
        const filtered = renderTab({ vuln: "CVE-2026-1" }).container.textContent;
        expect(filtered).toContain("Not affected by this advisory");
        cleanup();

        const notScanned = renderTab({ summary: undefined }).container.textContent;
        expect(notScanned).toContain("Not scanned");
        cleanup();

        const clean = renderTab({ summary: summary({}) }).container.textContent;
        expect(clean).toContain("No known vulnerabilities");
        expect(clean).not.toContain("Not scanned");
    });

    it("states that its scope is wider than the tile above it", () => {
        // The tile counts the newest SBOM; this list counts the newest SBOM per
        // version. Unexplained, the mismatch reads as a bug in one of them.
        const { container } = renderTab();
        expect(container.textContent).toContain("newest SBOM of each version");
    });
});
