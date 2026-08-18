// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { useCluster, useClusterWorkloads, useClusterVulns } from "~/api/queries";
import ClusterDetail from "./index";

// The mutation hooks are never called here, but StalenessPill lives in
// Clusters.tsx, which imports them at module scope — a factory that omitted
// them would fail the import rather than the assertion.
vi.mock("~/api/queries", () => ({
    useCluster: vi.fn(),
    useClusterWorkloads: vi.fn(),
    useClusterVulns: vi.fn(),
    useClusterNamespaces: vi.fn(),
    useListClusters: vi.fn(),
    useMyNamespaces: vi.fn(),
    useCreateCluster: vi.fn(),
    useUpdateCluster: vi.fn(),
    useDeleteCluster: vi.fn(),
}));

vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

let searchParams: Record<string, string | undefined> = {};

/** The last query params the workload hook was asked for. */
let lastWorkloadParams: { match_state?: string; limit?: number } | undefined;

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
    useParams: () => ({ id: "c-prod" }),
    useSearchParams: () => [searchParams, vi.fn()],
}));

const mockCluster = vi.mocked(useCluster);
const mockWorkloads = vi.mocked(useClusterWorkloads);
const mockVulns = vi.mocked(useClusterVulns);

const cluster = {
    id: "c-prod",
    name: "prod-eu-west",
    namespace_id: "ns-acme",
    namespace_name: "acme",
    last_seen_at: new Date().toISOString(),
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
};

function workload(overrides: Record<string, unknown> = {}) {
    return {
        id: "w1",
        cluster_id: "c-prod",
        k8s_namespace: "default",
        workload_kind: "Deployment",
        workload_name: "api",
        container_name: "api",
        image_ref: "ghcr.io/pfenerty/ocidex-api:v1",
        image_digest: "sha256:aaaabbbbccccdddd0000111122223333444455556666777788889999aaaabbbb",
        pod_count: 3,
        first_seen_at: "2026-08-01T00:00:00Z",
        last_seen_at: "2026-08-16T00:00:00Z",
        match_state: "exact",
        artifact_id: "a-1",
        artifact_name: "ocidex-api",
        sbom_id: "s-1",
        ...overrides,
    };
}

function vuln(overrides: Record<string, unknown> = {}) {
    return {
        id: "GHSA-xxxx",
        canonical_id: "CVE-2026-1000",
        severity: "CRITICAL",
        cvss_score: 9.8,
        summary: "Remote code execution",
        workload_count: 3,
        ...overrides,
    };
}

function renderPage(
    workloads: unknown[],
    coverage: { total: number; matched: number; unknown: number; unresolvable: number },
    vulns: unknown[] = [],
) {
    mockCluster.mockImplementation((() => ({
        data: cluster,
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockWorkloads.mockImplementation(((
        _id: unknown,
        params?: () => { match_state?: string; limit?: number },
    ) => {
        lastWorkloadParams = params?.();
        return {
            data: {
                data: workloads,
                coverage,
                pagination: { total: workloads.length, limit: 200, offset: 0 },
            },
            isLoading: false,
            isError: false,
            error: null,
        };
    }) as never);
    mockVulns.mockImplementation((() => ({
        data: { data: vulns, coverage, pagination: { total: vulns.length, limit: 5, offset: 0 } },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    return render(() => <ClusterDetail />);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

const GAPPY = { total: 10, matched: 4, unknown: 5, unresolvable: 1 };

describe("ClusterDetail", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        searchParams = {};
        lastWorkloadParams = undefined;
    });

    it("states coverage before any vulnerability figure", () => {
        const { container } = renderPage([workload()], GAPPY);

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        expect(tiles).toHaveLength(4);
        expect(must(tiles[1], "matched tile").textContent).toContain("4");
        expect(must(tiles[1], "matched tile").textContent).toContain("40%");
    });

    // The complaint this epic started from: the No-SBOM tile was tinted red on
    // every real cluster, so the tint carried no information and offered
    // nothing to do. Colour now marks selection; the gap survives as a link and
    // a stated remedy.
    it("does not raise a permanent alarm on the gap tiles", () => {
        const { container } = renderPage([workload()], GAPPY);

        for (const tile of container.querySelectorAll(".coverage-tile")) {
            expect(tile.className).not.toContain("bad");
            expect(tile.className).not.toContain("selected");
        }
    });

    // ADR-044 K5 still holds: an unassessed container must not read as a clean
    // one, so a non-zero gap is marked and states its remedy.
    it("keeps a non-zero gap visually distinct and actionable", () => {
        const { container } = renderPage([workload()], GAPPY);

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        const noSbom = must(tiles[2], "no-SBOM tile");
        expect(noSbom.className).toContain("gap");
        expect(noSbom.textContent).toContain("ingest to fix");
        expect(noSbom.getAttribute("href")).toBe("/clusters/c-prod?tab=gaps");

        const unresolvable = must(tiles[3], "unresolvable tile");
        expect(unresolvable.className).toContain("gap");
        expect(unresolvable.textContent).toContain("runtime gap");
    });

    it("marks no gap on a fully covered cluster", () => {
        const { container } = renderPage([workload()], {
            total: 4,
            matched: 4,
            unknown: 0,
            unresolvable: 0,
        });

        for (const tile of container.querySelectorAll(".coverage-tile")) {
            expect(tile.className).not.toContain("gap");
        }
        expect(container.querySelector(".coverage-caveat")).toBeNull();
    });

    it("names the workloads excluded from the vulnerability counts", () => {
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        const caveat = must(container.querySelector(".coverage-caveat"), "caveat");
        expect(caveat.textContent).toContain("6 running containers");
        expect(caveat.textContent).toContain("unknown, not zero");
    });

    it("shows the most severe running vulnerabilities on the overview", () => {
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        const list = must(container.querySelector(".overview-vuln-list"), "vuln list");
        expect(list.textContent).toContain("CVE-2026-1000");
        expect(list.textContent).toContain("3 workloads");
    });

    // A tab in the URL is what makes a filtered view something you can paste
    // into an issue.
    it("renders the tab named in the search param", () => {
        searchParams = { tab: "workloads" };
        const { container } = renderPage([workload()], GAPPY);

        const row = must(container.querySelector("tbody tr"), "workload row");
        expect(row.textContent).toContain("api");
        expect(container.querySelector(".overview-vuln-list")).toBeNull();
    });

    it("falls back to the overview for an unknown tab", () => {
        searchParams = { tab: "nonsense" };
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        expect(container.querySelector(".overview-vuln-list")).not.toBeNull();
    });

    // An unrecognised state would otherwise be forwarded to the API, which
    // would match nothing and show an empty table as if the cluster were empty.
    it("ignores a match_state the API does not define", () => {
        searchParams = { tab: "workloads", match_state: "bogus" };
        renderPage([workload()], GAPPY);

        expect(lastWorkloadParams?.match_state).toBeUndefined();
    });

    it("marks the tile whose rows are on screen", () => {
        searchParams = { tab: "workloads", match_state: "exact" };
        const { container } = renderPage([workload()], GAPPY);

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        expect(must(tiles[1], "matched tile").className).toContain("selected");
        expect(must(tiles[0], "containers tile").className).not.toContain("selected");
    });

    it("labels every match state in words, not colour alone", () => {
        const states = [
            ["exact", "matched"],
            ["index", "index match"],
            ["unknown", "no SBOM"],
            ["unresolvable", "no digest"],
        ] as const;
        for (const [state, label] of states) {
            searchParams = { tab: "workloads" };
            const { container, unmount } = renderPage([workload({ match_state: state })], {
                total: 1,
                matched: state === "exact" || state === "index" ? 1 : 0,
                unknown: state === "unknown" ? 1 : 0,
                unresolvable: state === "unresolvable" ? 1 : 0,
            });
            const row = must(container.querySelector("tbody tr"), "workload row");
            expect(row.textContent).toContain(label);
            unmount();
        }
    });

    it("links a matched workload to its artifact and SBOM", () => {
        searchParams = { tab: "workloads" };
        const { container } = renderPage([workload()], GAPPY);

        const row = must(container.querySelector("tbody tr"), "workload row");
        const hrefs = [...row.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(hrefs).toContain("/artifacts/a-1");
        expect(hrefs).toContain("/sboms/s-1");
    });

    // The two gaps have different remedies, so they are stated separately
    // rather than summed into one "not covered" number.
    it("separates the two gaps by remedy", () => {
        searchParams = { tab: "gaps" };
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("No SBOM ingested");
        expect(container.textContent).toContain("No digest readable");
        expect(container.textContent).toContain("scanning the image will not help");
    });
});
