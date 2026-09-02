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

function stubQuery(
    rows: ArtifactVulnEntry[],
    scope: { versionScope: number; totalVersions: number } = { versionScope: 20, totalVersions: 3 },
): void {
    mockVulns.mockImplementation((_id, params) => {
        lastParams = params?.() as Record<string, unknown> | undefined;
        return {
            data: {
                data: rows,
                pagination: { total: rows.length, limit: 50, offset: 0 },
                ...scope,
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
        expect(container.textContent).toContain("newest SBOM of each");
    });

    // The server caps how many versions it scans (ocidex-7gf7.5). A cap the
    // page does not mention turns "clean in the last 20 releases" into an
    // unqualified "clean", which is a worse failure than the timeout the cap
    // replaced — so both sides of the truncation are asserted here.
    it("names the cap and the history it leaves out when the scan is truncated", () => {
        stubQuery([vuln({})], { versionScope: 20, totalVersions: 1025 });
        const { container } = renderTab();
        expect(container.textContent).toContain("20 most recent versions");
        expect(container.textContent).toContain("1,025 in all");
    });

    it("says so plainly when nothing was left out", () => {
        stubQuery([vuln({})], { versionScope: 20, totalVersions: 3 });
        const { container } = renderTab();
        expect(container.textContent).toContain("each of this artifact's 3 versions");
        expect(container.textContent).not.toContain("most recent versions");
    });
});

// Same change as the SBOM tab's affected packages (ocidex-7gf7.9): the versions
// are already on the row, so they are shown rather than gated.
describe("Artifact VulnerabilitiesTab affected versions", () => {
    const versions = (n: number) =>
        Array.from({ length: n }, (_, i) => ({
            version: `1.0.${i}`,
            sbomId: `sbom-${i}`,
            affectedPackageCount: 1,
            packageNames: ["apt"],
        }));

    it("names them without waiting for a click", () => {
        stubQuery([vuln({ affectedVersionCount: 2, affectedVersions: versions(2) })]);
        const { container } = renderTab();
        const list = container.querySelector(".affected-versions");
        expect(list?.textContent).toContain("1.0.0");
        expect(list?.textContent).toContain("1.0.1");
        expect(container.querySelector(".affected-more")).toBeNull();
    });

    it("shows the first three and offers the rest by count", () => {
        stubQuery([vuln({ affectedVersionCount: 9, affectedVersions: versions(9) })]);
        const { container } = renderTab();
        expect(container.querySelectorAll(".affected-versions li")).toHaveLength(3);
        expect(container.querySelector(".affected-more")?.textContent).toBe("+6 more");
    });

    it("shows every one once expanded", () => {
        expandedKeys.add("CVE-2026-1");
        stubQuery([vuln({ affectedVersionCount: 9, affectedVersions: versions(9) })]);
        const { container } = renderTab();
        expect(container.querySelectorAll(".affected-versions li")).toHaveLength(9);
    });
});

// The caption reads two fields the server only started sending with the version
// cap (ocidex-7gf7.5). A web tier that is briefly ahead of the API during a
// rolling deploy gets neither, and reading them unguarded threw inside a
// reactive render — which does not surface as an error, it just leaves the tab
// frozen on its loading skeleton with no way back.
describe("Artifact VulnerabilitiesTab against a server with no version cap", () => {
    it("still lists the findings, and says only what it knows", () => {
        stubQuery(
            [vuln({})],
            {} as unknown as { versionScope: number; totalVersions: number },
        );
        const { container } = renderTab();
        expect(container.querySelectorAll("tbody tr").length).toBeGreaterThan(0);
        expect(container.textContent).toContain("Across the newest SBOM of each version.");
        expect(container.textContent).not.toContain("most recent versions");
    });
});
