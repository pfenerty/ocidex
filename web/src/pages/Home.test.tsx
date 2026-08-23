// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { useDashboardStats, useDiscovery } from "~/api/queries";
import Home from "~/pages/Home";
import type { JSX } from "solid-js";

// HomeBand is mounted by Home and reads three self-scoped queries plus the
// session. Stubbing them signed-out keeps this file about the catalog stats —
// HomeBand's own behaviour is covered in HomeBand.test.tsx.
vi.mock("~/api/queries", () => ({
    useDashboardStats: vi.fn(),
    useDiscovery: vi.fn(),
    useMyNamespaces: () => ({ data: undefined }),
    useMyDriftFeed: () => ({ data: undefined }),
    useWatches: () => ({ data: undefined }),
}));

vi.mock("~/context/auth", () => ({
    useAuth: () => ({ user: () => undefined, refetch: vi.fn() }),
}));

vi.mock("@solidjs/router", () => ({
    // Forward class: the type chips are selected by their class in the
    // assertions below, and a stub that drops it makes them invisible to the test.
    A: (props: { href: string; class?: string; children?: JSX.Element }) => (
        <a href={props.href} class={props.class}>{props.children}</a>
    ),
}));

const mockUseStats = vi.mocked(useDashboardStats);
const mockUseDiscovery = vi.mocked(useDiscovery);

interface DiscoveryData {
    top_artifacts: {
        id: string;
        type: string;
        name: string;
        usageCount: number;
        versionCount: number;
        sbomCount: number;
        score: number;
        purl?: string;
    }[];
    recent_artifacts: {
        artifactId: string;
        type: string;
        name: string;
        sbomId: string;
        createdAt: string;
        subjectVersion?: string;
    }[];
    top_vulnerabilities: {
        id: string;
        canonicalId: string;
        severity: string;
        affectedArtifactCount: number;
        affectedSbomCount: number;
        summary?: string;
    }[];
    license_spread: {
        id: string;
        name: string;
        category: string;
        componentCount: number;
        spdxId?: string;
    }[];
    warming?: boolean;
}

interface DiscoveryQuery {
    isError: boolean;
    data: DiscoveryData | undefined;
}

/** A snapshot with one row in each section — enough to assert every link. */
function populatedDiscovery(): DiscoveryData {
    return {
        top_artifacts: [
            {
                id: "art-1",
                type: "container",
                name: "alpine",
                usageCount: 14,
                versionCount: 3,
                sbomCount: 9,
                score: 12.5,
            },
        ],
        recent_artifacts: [
            {
                artifactId: "art-2",
                type: "container",
                name: "nginx",
                sbomId: "sbom-9",
                createdAt: new Date().toISOString(),
                subjectVersion: "1.27",
            },
        ],
        top_vulnerabilities: [
            {
                id: "vuln-1",
                canonicalId: "CVE-2024-1234",
                severity: "CRITICAL",
                affectedArtifactCount: 7,
                affectedSbomCount: 21,
            },
        ],
        license_spread: [
            { id: "lic-1", name: "MIT License", category: "permissive", componentCount: 4210, spdxId: "MIT" },
        ],
    };
}

const emptyDiscovery: DiscoveryData = {
    top_artifacts: [],
    recent_artifacts: [],
    top_vulnerabilities: [],
    license_spread: [],
};

interface StatsQuery {
    isLoading: boolean;
    isError: boolean;
    data:
        | {
              artifact_count: number;
              sbom_count: number;
              version_count: number;
              package_count: number;
              license_count: number;
              vuln_count: number;
              artifact_types?: { type: string; artifact_count: number }[] | null;
              warming?: boolean;
          }
        | undefined;
}

function renderHome(query: StatsQuery, discovery?: DiscoveryQuery) {
    // The component only reads these three fields off the query.
    mockUseStats.mockReturnValue(query as unknown as ReturnType<typeof useDashboardStats>);
    mockUseDiscovery.mockReturnValue(
        (discovery ?? { isError: false, data: emptyDiscovery }) as unknown as ReturnType<
            typeof useDiscovery
        >,
    );
    return render(() => <Home />);
}

// The landing page is the one route an anonymous visitor always hits first.
// It used to bounce to /login because HomeBand's three /users/me/* queries ran
// unconditionally and unwrap() hard-navigated on any 401 (ocidex-ag4q.1/.2).
// Both mechanisms are gone; this pins the outcome at the page level, and
// Layout.test.tsx pins that "/" is not an authed path.
describe("Home for signed-out visitors", () => {
    it("renders the catalog without navigating to /login", () => {
        const before = window.location.pathname;
        const { container } = renderHome(
            {
                isLoading: false,
                isError: false,
                data: {
                    artifact_count: 38,
                    sbom_count: 214,
                    version_count: 57,
                    package_count: 107868,
                    license_count: 545,
                    vuln_count: 12,
                },
            },
            { isError: false, data: populatedDiscovery() },
        );

        expect(container.textContent).toContain("38");
        expect(container.textContent).not.toContain("Catalog stats are unavailable");
        expect(window.location.pathname).toBe(before);
    });
});

describe("Home catalog stats", () => {
    it("renders the counts once stats load", () => {
        const { container } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 38,
                sbom_count: 214,
                version_count: 57,
                package_count: 107868,
                license_count: 545,
                vuln_count: 12,
            },
        });
        // Head and value are separate spans in a StatBand, so assert on the
        // tile rather than on a concatenated "38 artifacts" string.
        const tiles = [...container.querySelectorAll(".tile")].map((t) => t.textContent);
        expect(tiles).toContain("Artifacts38images, binaries and libraries");
        expect(tiles).toContain("Packages107,86857 versions indexed");
        // Every tile that has a list page behind it links to it; SBOMs does not.
        const hrefs = [...container.querySelectorAll("a.tile")].map((a) => a.getAttribute("href"));
        expect(hrefs).toEqual(["/artifacts", "/components", "/licenses", "/vulnerabilities"]);
    });

    // Regression: the stats query times out against a cold cache, and a bare
    // <Show> rendered that as nothing at all — visually identical to an empty
    // catalog, which is why the failure went unnoticed in production.
    it("says stats are unavailable rather than rendering nothing on error", () => {
        const { container } = renderHome({ isLoading: false, isError: true, data: undefined });
        expect(container.textContent).toContain("Catalog stats are unavailable");
    });

    it("shows a placeholder while stats are still loading", () => {
        const { container } = renderHome({ isLoading: true, isError: false, data: undefined });
        expect(container.querySelector(".skeleton")).not.toBeNull();
        expect(container.textContent).not.toContain("Catalog stats are unavailable");
    });

    // --- artifact-type breakdown (ocidex-l1e0) -------------------------------

    it("renders a linked chip per artifact type", () => {
        const { container } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 38,
                sbom_count: 214,
                version_count: 57,
                package_count: 0,
                license_count: 0,
                vuln_count: 0,
                artifact_types: [
                    { type: "container", artifact_count: 24 },
                    { type: "library", artifact_count: 9 },
                    { type: "application", artifact_count: 5 },
                ],
            },
        });

        // Scoped to the chip row: the discovery panels link to /artifacts too,
        // so a page-wide link query matches more than the chips.
        const chips = [...container.querySelectorAll(".landing-type")];
        expect(chips.map((c) => c.getAttribute("href"))).toEqual([
            "/artifacts?type=container",
            "/artifacts?type=library",
            "/artifacts?type=application",
        ]);
        expect(chips[0].textContent).toContain("24");
    });

    // A stranger who reads only the top of this page should leave it with a
    // destination. The band's tiles are figures; these are verbs, and there are
    // three of them on purpose (ocidex-ag4q.42).
    it("offers three entry points into the catalog", () => {
        const { container } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 38,
                sbom_count: 214,
                version_count: 57,
                package_count: 107868,
                license_count: 545,
                vuln_count: 12,
            },
        });

        const ctas = [...(container.querySelector(".landing-ctas")?.children ?? [])];
        expect(ctas.map((c) => c.textContent)).toEqual([
            "Browse artifacts",
            "Search components",
            "Review vulnerabilities",
            "GitHub",
        ]);
        expect(ctas.slice(0, 3).map((c) => c.getAttribute("href"))).toEqual([
            "/artifacts",
            "/components",
            "/vulnerabilities",
        ]);
        // Exactly one red thing per view, per the token split in index.css.
        expect(container.querySelectorAll(".landing-ctas .btn-primary")).toHaveLength(1);
    });

    // The field is nullable in the generated spec, and an empty catalog has no
    // types at all — the rest of the hero must still render.
    it("omits the chip row when no types come back", () => {
        const { container } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 0,
                sbom_count: 0,
                version_count: 0,
                package_count: 0,
                license_count: 0,
                vuln_count: 0,
                artifact_types: null,
            },
        });

        expect(container.querySelector(".landing-types")).toBeNull();
        expect(container.querySelector(".tile-value")?.textContent).toBe("0");
    });

    // A warming response is a successful 200 whose counts are all zero
    // placeholders — the snapshot is computed out of band by the background
    // warmer. Rendering it verbatim claims an empty catalog.
    it("keeps the placeholder when the server reports it is still warming", () => {
        const { container } = renderHome({
            isLoading: false,
            isError: false,
            data: {
                artifact_count: 0,
                sbom_count: 0,
                version_count: 0,
                package_count: 0,
                license_count: 0,
                vuln_count: 0,
                warming: true,
            },
        });
        expect(container.querySelector(".skeleton")).not.toBeNull();
        expect(container.querySelector(".tile")).toBeNull();
    });
});

// --- live discovery panels (ocidex-q1z7.3) -----------------------------------

const warmStats: StatsQuery = {
    isLoading: false,
    isError: false,
    data: { artifact_count: 1, sbom_count: 1, version_count: 1, package_count: 1, license_count: 1, vuln_count: 1 },
};

describe("Home discovery panels", () => {
    it("links every ranked row into its detail page", () => {
        const { container, getByText } = renderHome(warmStats, {
            isError: false,
            data: populatedDiscovery(),
        });

        const hrefs = [...container.querySelectorAll(".landing-list-row a")].map((a) =>
            a.getAttribute("href"),
        );
        expect(hrefs).toContain("/artifacts/art-1");
        expect(hrefs).toContain("/artifacts/art-2");
        // The recent row points at the SBOM that produced the timestamp, which
        // is the thing that actually changed.
        expect(hrefs).toContain("/sboms/sbom-9");
        expect(hrefs).toContain("/vulnerabilities/CVE-2024-1234");
        expect(hrefs).toContain("/licenses/lic-1/components");

        expect(getByText("alpine")).toBeDefined();
        expect(getByText("14 uses · 3 versions")).toBeDefined();
        // Blast radius is reported in artifacts, not SBOMs: the SBOM count
        // (21 here) double-counts every rescan of the same image.
        expect(getByText("7 artifacts")).toBeDefined();
        expect(container.textContent).not.toContain("21 sboms");
    });

    // A warming response is a successful 200 with four empty sections because
    // the server has not measured the catalog yet. Rendering it as "nothing
    // here" reports an empty catalog — the same failure the stats band guards.
    it("shows the loading state, not empty panels, while the server is warming", () => {
        const { container } = renderHome(warmStats, {
            isError: false,
            data: { ...emptyDiscovery, warming: true },
        });

        expect(container.querySelector(".landing-discover-loading")).not.toBeNull();
        expect(container.querySelector(".landing-features-grid")).toBeNull();
        expect(container.textContent).not.toContain("Nothing indexed yet");
    });

    it("says highlights are unavailable on error rather than rendering nothing", () => {
        const { container } = renderHome(warmStats, { isError: true, data: undefined });

        expect(container.textContent).toContain("Catalog highlights are unavailable");
        expect(container.querySelector(".landing-features-grid")).toBeNull();
        expect(container.querySelector(".landing-discover-loading")).toBeNull();
    });

    // The three states must stay distinguishable at the far end too: a warm
    // snapshot of a genuinely empty catalog says so, and does not look like a
    // page that is still loading.
    it("says a section is empty when a warm snapshot has no rows", () => {
        const { container } = renderHome(warmStats, { isError: false, data: emptyDiscovery });

        expect(container.querySelector(".landing-features-grid")).not.toBeNull();
        expect(container.querySelector(".landing-discover-loading")).toBeNull();
        expect(container.textContent).toContain("Nothing indexed yet");
        expect(container.textContent).toContain("No known vulnerabilities");
    });
});
