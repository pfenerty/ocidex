// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { useDashboardStats, useDiscovery } from "~/api/queries";
import type { DiscoverFeatured } from "~/api/queries";
import Home from "~/pages/Home";
import { criticalSeries, packageHref } from "~/pages/HomeDiscovery";
import type { JSX } from "solid-js";

// HomeBand is mounted by Home and reads self-scoped queries plus the session.
// Stubbing them signed-out keeps this file about the catalog; HomeBand's own
// behaviour is covered in HomeBand.test.tsx.
vi.mock("~/api/queries", () => ({
    useDashboardStats: vi.fn(),
    useDiscovery: vi.fn(),
    useMyNamespaces: () => ({ data: undefined }),
    useMyDriftFeed: () => ({ data: undefined }),
    useWatches: () => ({ data: undefined }),
    useMyClusters: () => ({ data: undefined }),
}));

vi.mock("~/context/auth", () => ({
    useAuth: () => ({ user: () => undefined, refetch: vi.fn() }),
}));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; class?: string; children?: JSX.Element }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

const featured = (name: string, over: Partial<DiscoverFeatured> = {}): DiscoverFeatured =>
    ({
        artifactId: `art-${name}`,
        type: "container",
        name: `registry-1.docker.io/library/${name}`,
        sbomId: `sbom-${name}`,
        createdAt: "2026-11-18T00:00:00Z",
        builtAt: "2026-11-17T00:00:00Z",
        subjectVersion: "1.31.9",
        packageCount: 100,
        tagCount: 4,
        vulns: { critical: 11, high: 77, medium: 100, low: 46, unknown: 0, fixable: 0 },
        licenses: { permissive: 1, weakCopyleft: 0, copyleft: 0, uncategorized: 0 },
        vulnMatched: true,
        criticalHistory: [
            { versionKey: "1.31.9", architecture: "amd64", critical: 11 },
            { versionKey: "1.31.9-alpine", architecture: "amd64", critical: 2 },
            { versionKey: "1.31.8", architecture: "amd64", critical: 15 },
            { versionKey: "1.31.7", architecture: "amd64", critical: 20 },
        ],
        ...over,
    });

const discovery = {
    featuredArtifacts: [featured("nginx"), featured("postgres", { criticalHistory: [], tagCount: 1 })],
    topPackages: [
        { ecosystem: "golang", name: "stdlib", sbomCount: 6966, versionCount: 87, critical: 8, high: 86 },
        { ecosystem: "maven", name: "guava", group: "com.google.guava", sbomCount: 452, versionCount: 5, critical: 0, high: 1 },
    ],
    criticalCuts: [
        {
            artifactId: "a-dex",
            name: "ghcr.io/dexidp/dex",
            fromSbomId: "f",
            fromVersion: "v2.45.1",
            fromCritical: 16,
            toSbomId: "t",
            toVersion: "v2.46.0",
            toCritical: 3,
            releasedAt: "2026-10-07T00:00:00Z",
        },
    ],
    topArtifacts: [],
    recentArtifacts: [],
    topVulnerabilities: [],
    licenseSpread: [],
    warming: false,
};

const stats = {
    isLoading: false,
    isError: false,
    data: {
        artifactCount: 141,
        sbomCount: 8412,
        versionCount: 1,
        packageCount: 7355,
        licenseCount: 1088,
        vulnCount: 10479,
        warming: false,
    },
};

function renderHome(opts: { stats?: unknown; discovery?: unknown } = {}) {
    vi.mocked(useDashboardStats).mockReturnValue((opts.stats ?? stats) as never);
    vi.mocked(useDiscovery).mockReturnValue(
        (opts.discovery ?? { isLoading: false, isError: false, error: undefined, data: discovery }) as never,
    );
    return render(() => <Home />);
}

describe("Home", () => {
    it("opens with one line and search, not display type or a narrative headline", () => {
        const { container } = renderHome();
        expect(container.querySelector("h1")?.textContent).toBe("What's inside the container images you already pull");
        expect(container.querySelector(".home-search")?.textContent).toContain("Look up an image, package or CVE");
    });

    it("lists featured images in the given order with tag, counts and tag count", () => {
        const { getByLabelText } = renderHome();
        const rows = getByLabelText("Images you've probably pulled").querySelectorAll("a.home-img");
        expect(rows).toHaveLength(2);
        expect(rows[0].getAttribute("href")).toBe("/artifacts/art-nginx");
        expect(rows[0].textContent).toContain("nginx");
        expect(rows[0].textContent).toContain("1.31.9");
        expect(rows[0].textContent).toContain("234"); // all CVEs
        expect(rows[0].textContent).toContain("20 → 11");
        expect(rows[1].textContent).toContain("postgres");
        expect(rows[1].textContent).toContain("one tag so far");
    });

    it("lists the top packages with a link filtered to their ecosystem", () => {
        const { getByLabelText } = renderHome();
        const section = getByLabelText("Packages found in the most SBOMs");
        expect(section.textContent).toContain("Out of 8,412 SBOMs.");
        const rows = section.querySelectorAll("a.home-pkg");
        expect(rows[0].textContent).toContain("stdlib");
        expect(rows[0].textContent).toContain("6,966");
        expect(rows[0].getAttribute("href")).toBe("/components?name=stdlib&purlType=golang");
    });

    it("lists releases that cut criticals, linked to their diff", () => {
        const { getByLabelText } = renderHome();
        const row = getByLabelText("Releases that cut criticals").querySelector("a.home-cut");
        expect(row?.getAttribute("href")).toBe("/diff?from=f&to=t");
        expect(row?.textContent).toContain("v2.45.1 → v2.46.0");
        expect(row?.textContent).toContain("16 → 3");
    });

    it("closes with catalog totals", () => {
        const { container } = renderHome();
        expect(container.querySelector(".home-facts")?.textContent).toContain("141 artifacts");
    });

    it("says stats are unavailable rather than rendering nothing on error", () => {
        const { getByText } = renderHome({ stats: { isLoading: false, isError: true, data: undefined } });
        expect(getByText("Catalog stats are unavailable.")).toBeTruthy();
    });

    it("shows a loading state, not empty tables, while the server is warming", () => {
        const { container } = renderHome({
            discovery: { isLoading: false, isError: false, error: undefined, data: { ...discovery, warming: true } },
        });
        expect(container.querySelector(".home-loading")).not.toBeNull();
        expect(container.querySelector(".home-img")).toBeNull();
    });

    it("says highlights are unavailable on error", () => {
        const { getByText } = renderHome({
            discovery: { isLoading: false, isError: true, error: new Error("x"), data: undefined },
        });
        expect(getByText("Catalog highlights are unavailable.")).toBeTruthy();
    });

    it("omits the featured table when nothing is featured", () => {
        const { queryByLabelText } = renderHome({
            discovery: {
                isLoading: false,
                isError: false,
                error: undefined,
                data: { ...discovery, featuredArtifacts: [] },
            },
        });
        expect(queryByLabelText("Images you've probably pulled")).toBeNull();
    });
});

describe("helpers", () => {
    it("criticalSeries keeps the newest point's line and arch, oldest first", () => {
        expect(criticalSeries(featured("nginx"))).toEqual([20, 15, 11]);
    });

    it("criticalSeries skips unscanned versions", () => {
        const f = featured("x", {
            criticalHistory: [
                { versionKey: "2", architecture: "amd64", critical: 1 },
                { versionKey: "1", architecture: "amd64" },
                { versionKey: "0", architecture: "amd64", critical: 4 },
            ],
        });
        expect(criticalSeries(f)).toEqual([4, 1]);
    });

    it("packageHref carries the group when there is one", () => {
        expect(packageHref(discovery.topPackages[1])).toBe(
            "/components?name=guava&purlType=maven&group=com.google.guava",
        );
    });
});
