// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { useCluster, useClusterWorkloads, useRunningVulnSummaries } from "~/api/queries";
import ClusterDetail from "~/pages/ClusterDetail";

// The last five are never called here, but StalenessPill lives in Clusters.tsx,
// which imports them at module scope — a factory that omitted them would fail
// the import rather than the assertion.
vi.mock("~/api/queries", () => ({
    useCluster: vi.fn(),
    useClusterWorkloads: vi.fn(),
    useRunningVulnSummaries: vi.fn(),
    useListClusters: vi.fn(),
    useMyNamespaces: vi.fn(),
    useCreateCluster: vi.fn(),
    useUpdateCluster: vi.fn(),
    useDeleteCluster: vi.fn(),
}));

vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
    useParams: () => ({ id: "c-prod" }),
}));

const mockCluster = vi.mocked(useCluster);
const mockWorkloads = vi.mocked(useClusterWorkloads);
const mockRunning = vi.mocked(useRunningVulnSummaries);

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

const EMPTY_SUMMARY = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 };

function renderPage(
    workloads: unknown[],
    coverage: { total: number; matched: number; unknown: number; unresolvable: number },
    totals = EMPTY_SUMMARY,
) {
    mockCluster.mockImplementation((() => ({
        data: cluster,
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockWorkloads.mockImplementation((() => ({
        data: { data: workloads, coverage },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockRunning.mockImplementation((() =>
        () => ({ isPending: false, isError: false, totals, rows: [] })));
    return render(() => <ClusterDetail />);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

describe("ClusterDetail", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("states coverage before any vulnerability figure", () => {
        const { container } = renderPage([workload()], {
            total: 10,
            matched: 4,
            unknown: 5,
            unresolvable: 1,
        });

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        expect(tiles).toHaveLength(4);
        expect(must(tiles[1], "matched tile").textContent).toContain("4");
        expect(must(tiles[1], "matched tile").textContent).toContain("40%");
    });

    // ADR-044 K5: an unassessed workload must never render like a clean one.
    it("tints the gap tiles and leaves matched untinted", () => {
        const { container } = renderPage([workload()], {
            total: 10,
            matched: 4,
            unknown: 5,
            unresolvable: 1,
        });

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        expect(must(tiles[1], "matched tile").className).toBe("coverage-tile");
        expect(must(tiles[2], "no-SBOM tile").className).toContain("bad");
        expect(must(tiles[3], "unresolvable tile").className).toContain("warn");
    });

    it("does not tint a fully covered cluster", () => {
        const { container } = renderPage([workload()], {
            total: 4,
            matched: 4,
            unknown: 0,
            unresolvable: 0,
        });

        for (const tile of container.querySelectorAll(".coverage-tile")) {
            expect(tile.className).toBe("coverage-tile");
        }
        expect(container.querySelector(".coverage-caveat")).toBeNull();
    });

    it("names the workloads excluded from the vulnerability counts", () => {
        const { container } = renderPage([workload()], {
            total: 10,
            matched: 4,
            unknown: 5,
            unresolvable: 1,
        });

        const caveat = must(container.querySelector(".coverage-caveat"), "caveat");
        expect(caveat.textContent).toContain("6 running containers");
        expect(caveat.textContent).toContain("unknown, not zero");
    });

    // Counting an artifact once per workload would multiply the totals by however
    // many replicas of the same image happen to be deployed.
    it("scopes vulnerabilities to distinct running artifacts", () => {
        renderPage(
            [
                workload(),
                workload({ id: "w2", workload_name: "api-canary", artifact_id: "a-1" }),
                workload({ id: "w3", workload_name: "worker", artifact_id: "a-2" }),
                workload({
                    id: "w4",
                    workload_name: "legacy",
                    match_state: "unknown",
                    artifact_id: undefined,
                    sbom_id: undefined,
                }),
            ],
            { total: 4, matched: 3, unknown: 1, unresolvable: 0 },
        );

        const idsAccessor = mockRunning.mock.calls[0][0];
        expect(idsAccessor()).toEqual(["a-1", "a-2"]);
    });

    it("reports a clean result as a coverage gap when nothing matched", () => {
        const { container } = renderPage(
            [workload({ match_state: "unresolvable", artifact_id: undefined, sbom_id: undefined })],
            { total: 1, matched: 0, unknown: 0, unresolvable: 1 },
        );

        expect(container.textContent).toContain("coverage gap, not a clean result");
    });

    it("labels every match state in words, not colour alone", () => {
        const states = [
            ["exact", "matched"],
            ["index", "index match"],
            ["unknown", "no SBOM"],
            ["unresolvable", "no digest"],
        ] as const;
        for (const [state, label] of states) {
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
        const { container } = renderPage([workload()], {
            total: 1,
            matched: 1,
            unknown: 0,
            unresolvable: 0,
        });

        const row = must(container.querySelector("tbody tr"), "workload row");
        const hrefs = [...row.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(hrefs).toContain("/artifacts/a-1");
        expect(hrefs).toContain("/sboms/s-1");
    });

    it("reports the totals it was given for the matched images", () => {
        const { container } = renderPage(
            [workload()],
            { total: 1, matched: 1, unknown: 0, unresolvable: 0 },
            { critical: 2, high: 1, medium: 0, low: 0, unknown: 0, total: 3 },
        );

        expect(container.textContent).toContain("3 known vulnerabilities");
        expect(container.textContent).toContain("1 distinct image");
    });
});
