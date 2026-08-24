// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import {
    useCluster,
    useClusterWorkloads,
    useClusterImages,
    useClusterVulns,
    useClusterNamespaces,
    useVulnWorkloads,
    useClusterUnknownImages,
    useIngestUnknown,
} from "~/api/queries";
import ClusterDetail from "./index";

// The mutation hooks are never called here, but StalenessPill lives in
// Clusters.tsx, which imports them at module scope — a factory that omitted
// them would fail the import rather than the assertion.
vi.mock("~/api/queries", () => ({
    useCluster: vi.fn(),
    useClusterWorkloads: vi.fn(),
    useClusterImages: vi.fn(),
    useClusterVulns: vi.fn(),
    useClusterNamespaces: vi.fn(),
    useVulnWorkloads: vi.fn(),
    useClusterUnknownImages: vi.fn(),
    useIngestUnknown: vi.fn(),
    useListClusters: vi.fn(),
    useMyNamespaces: vi.fn(),
    useCreateCluster: vi.fn(),
    useUpdateCluster: vi.fn(),
    useDeleteCluster: vi.fn(),
}));

vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

let searchParams: Record<string, string | undefined> = {};

/** The last query params the workload hook was asked for. */
let lastWorkloadParams:
    | {
          match_state?: string;
          k8s_namespace?: string;
          q?: string;
          sort?: string;
          dir?: string;
          limit?: number;
          offset?: number;
      }
    | undefined;

/** One setSearchParams call: the keys the page writes, undefined meaning cleared. */
/** The last query params the image hook was asked for. */
let lastImageParams:
    | {
          match_state?: string;
          k8s_namespace?: string;
          q?: string;
          sort?: string;
          dir?: string;
          limit?: number;
          offset?: number;
      }
    | undefined;

interface ParamWrite {
    tab?: string;
    group?: string;
    k8s_namespace?: string;
    match_state?: string;
    q?: string;
    sort?: string;
    dir?: string;
    offset?: number;
}

/** The last query params the running-vulnerability hook was asked for. */
let lastVulnParams:
    | { severity?: string; sort?: string; dir?: string; limit?: number; offset?: number }
    | undefined;

/**
 * The last reverse-workload lookup's arguments, kept as the accessors the hook
 * was handed rather than their values: `enabled` is what the row expansion
 * changes, and reading it once at call time would only ever see the closed
 * state.
 */
let lastVulnWorkloadArgs:
    | {
          canonicalId: () => string | undefined;
          clusterId?: () => string | undefined;
          options?: () => { enabled?: boolean };
      }
    | undefined;

/** Search-param writes the page made, newest last. */
let searchParamWrites: ParamWrite[] = [];

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
    useParams: () => ({ id: "c-prod" }),
    useSearchParams: () => [
        searchParams,
        (next: ParamWrite) => {
            searchParamWrites.push(next);
        },
    ],
}));

const mockCluster = vi.mocked(useCluster);
const mockWorkloads = vi.mocked(useClusterWorkloads);
const mockImages = vi.mocked(useClusterImages);
const mockVulns = vi.mocked(useClusterVulns);
const mockNamespaces = vi.mocked(useClusterNamespaces);
const mockVulnWorkloads = vi.mocked(useVulnWorkloads);
const mockUnknownImages = vi.mocked(useClusterUnknownImages);
const mockIngest = vi.mocked(useIngestUnknown);

/** Whether the rendered cluster has auto-ingest on; the ingest tests set this. */
let autoIngest = true;

const cluster = {
    id: "c-prod",
    name: "prod-eu-west",
    namespace_id: "ns-acme",
    namespace_name: "acme",
    last_seen_at: new Date().toISOString(),
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
};

/** Every ingest run the page asked for, in order. */
let ingestCalls: { id: string; imageDigests?: string[] }[] = [];

/** The result the ingest mutation reports as its last outcome, if any. */
let ingestResult: Record<string, number> | undefined;

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

function image(overrides: Record<string, unknown> = {}) {
    return {
        image_ref: "ghcr.io/pfenerty/ocidex-api:v1",
        image_digest: "sha256:aaaabbbbccccdddd0000111122223333444455556666777788889999aaaabbbb",
        workload_count: 4,
        pod_count: 12,
        namespace_count: 2,
        sample_namespace: "default",
        sample_workload: "api",
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

/** Rows the unknown-image hook returns; the gaps tests set this. */
let unknownImages: unknown[] = [];

/**
 * The whole-gap figures the server sends beside the page.
 *
 * Left unset they are derived from `unknownImages`, which is the truthful
 * answer while the fixture fits on one page. The truncation tests set them
 * directly to describe a gap larger than the page they are handed.
 */
let unknownGap: { total: number; reasons: Record<string, number> } | undefined;

const NO_REASONS = {
    ready: 0,
    no_registry: 0,
    registry_disabled: 0,
    pattern_excluded: 0,
    unparseable_ref: 0,
};

/** Tallies the fixture the way the server tallies the gap. */
function reasonsOf(rows: unknown[]): Record<string, number> {
    const tally = { ...NO_REASONS };
    for (const row of rows as { reason?: string }[]) {
        if (row.reason !== undefined) tally[row.reason as keyof typeof tally]++;
    }
    return tally;
}

function unknownImage(overrides: Record<string, unknown> = {}) {
    return {
        image_ref: "ghcr.io/pfenerty/api:v1",
        image_digest: "sha256:aaaabbbbccccdddd0000111122223333444455556666777788889999aaaabbbb",
        registry_host: "ghcr.io",
        repository: "pfenerty/api",
        workload_count: 3,
        pod_count: 9,
        sample_k8s_namespace: "default",
        sample_workload_name: "api",
        reason: "ready",
        ...overrides,
    };
}

function renderPage(
    workloads: unknown[],
    coverage: { total: number; matched: number; unknown: number; unresolvable: number; pods: number },
    vulns: unknown[] = [],
    images: unknown[] = [image()],
) {
    mockIngest.mockImplementation((() => ({
        mutate: (vars: { id: string; imageDigests?: string[] }) => ingestCalls.push(vars),
        data: ingestResult,
        isPending: false,
        isError: false,
        error: null,
    })) as never);
    mockCluster.mockImplementation((() => ({
        data: { ...cluster, auto_ingest: autoIngest },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockWorkloads.mockImplementation(((
        _id: unknown,
        params?: () => NonNullable<typeof lastWorkloadParams>,
    ) => {
        lastWorkloadParams = params?.();
        return {
            data: {
                data: workloads,
                coverage,
                pagination: { total: workloads.length, limit: 50, offset: 0 },
            },
            isLoading: false,
            isFetching: false,
            isError: false,
            error: null,
        };
    }) as never);
    mockImages.mockImplementation(((
        _id: unknown,
        params?: () => NonNullable<typeof lastImageParams>,
    ) => {
        lastImageParams = params?.();
        return {
            data: {
                data: images,
                coverage,
                pagination: { total: images.length, limit: 50, offset: 0 },
            },
            isLoading: false,
            isFetching: false,
            isError: false,
            error: null,
        };
    }) as never);
    mockNamespaces.mockImplementation((() => ({
        data: {
            data: [
                { k8s_namespace: "default", workload_count: 7 },
                { k8s_namespace: "kube-system", workload_count: 3 },
            ],
        },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockVulns.mockImplementation(((
        _id: unknown,
        params?: () => NonNullable<typeof lastVulnParams>,
    ) => {
        lastVulnParams = params?.();
        return {
            data: {
                data: vulns,
                coverage,
                pagination: { total: vulns.length, limit: 50, offset: 0 },
            },
            isLoading: false,
            isFetching: false,
            isError: false,
            error: null,
        };
    }) as never);
    mockVulnWorkloads.mockImplementation(((
        canonicalId: () => string | undefined,
        clusterId?: () => string | undefined,
        options?: () => { enabled?: boolean },
    ) => {
        lastVulnWorkloadArgs = { canonicalId, clusterId, options };
        return {
            data: {
                data: [
                    {
                        cluster_id: "c-prod",
                        cluster_name: "prod-eu-west",
                        k8s_namespace: "payments",
                        workload_name: "checkout",
                        container_name: "app",
                        image_ref: "ghcr.io/pfenerty/checkout:v2",
                        pod_count: 2,
                    },
                ],
            },
            isLoading: false,
            isError: false,
            error: null,
        };
    }) as never);
    mockUnknownImages.mockImplementation((() => ({
        data: {
            data: unknownImages,
            reasons: unknownGap?.reasons ?? reasonsOf(unknownImages),
            pagination: {
                total: unknownGap?.total ?? unknownImages.length,
                limit: 50,
                offset: 0,
            },
        },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    return render(() => <ClusterDetail />);
}

/** The most recent setSearchParams call, or a failure if the page made none. */
function lastWrite(): ParamWrite {
    return must(searchParamWrites[searchParamWrites.length - 1], "a search-param write");
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

const GAPPY = { total: 10, matched: 4, unknown: 5, unresolvable: 1, pods: 23 };
const EMPTY = { total: 0, matched: 0, unknown: 0, unresolvable: 0, pods: 0 };

describe("ClusterDetail", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        searchParams = {};
        lastWorkloadParams = undefined;
        lastImageParams = undefined;
        lastVulnParams = undefined;
        lastVulnWorkloadArgs = undefined;
        unknownImages = [];
        unknownGap = undefined;
        searchParamWrites = [];
        ingestCalls = [];
        ingestResult = undefined;
        autoIngest = true;
    });

    it("states coverage before any vulnerability figure", () => {
        const { container } = renderPage([workload()], GAPPY);

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        expect(tiles).toHaveLength(4);
        expect(must(tiles[1], "matched tile").textContent).toContain("4");
        expect(must(tiles[1], "matched tile").textContent).toContain("40%");
    });

    // The tile counts workload-containers, which is the denominator every
    // vulnerability figure below it is computed over (ADR-044 K5). It used to
    // claim it was "deduplicated per image", which it never was — and a wrong
    // denominator is the failure K5 exists to prevent.
    it("labels the containers tile with what it actually counts", () => {
        const { container } = renderPage([workload()], GAPPY);

        const containers = must(
            container.querySelectorAll(".coverage-tile")[0],
            "containers tile",
        );
        expect(containers.textContent).toContain("10");
        expect(containers.textContent).toContain("workload containers");
        expect(containers.textContent).toContain("23 pods");
        expect(containers.textContent).not.toContain("deduplicated");
    });

    // The complaint this epic started from: the No-SBOM tile was tinted red on
    // every real cluster, so the tint carried no information and offered
    // nothing to do. Colour now marks selection; the gap survives as a link and
    // a stated remedy.
    it("does not raise a permanent alarm on the gap tiles", () => {
        const { container } = renderPage([workload()], GAPPY);

        for (const tile of container.querySelectorAll(".coverage-tile")) {
            expect(tile.className).not.toContain("bad");
            expect(tile.className).not.toContain("active");
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
            pods: 9,
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

    // R2b: the old row was [pill][id][count] in a flex line, and severity pills
    // are different widths, so nothing lined up and the row said nothing about
    // what the advisory actually is.
    it("carries the score and summary beside each advisory", () => {
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        const row = must(container.querySelector(".overview-vuln-list li"), "vuln row");
        expect(must(row.querySelector(".overview-vuln-cvss"), "cvss").textContent).toBe("9.8");
        const summary = must(row.querySelector(".overview-vuln-summary"), "summary");
        expect(summary.textContent).toBe("Remote code execution");
        // Clamped to one line, so the whole text has to survive as a title.
        expect(summary.getAttribute("title")).toBe("Remote code execution");
    });

    // A "487" badge beside five rows read as the length of the list under it.
    it("says how much of the list the card is showing", () => {
        const { container } = renderPage([workload()], GAPPY, [
            vuln(),
            vuln({ id: "GHSA-yyyy", canonical_id: "CVE-2026-1001" }),
        ]);

        const header = must(container.querySelector(".card-header"), "card header");
        expect(header.textContent).toContain("top 2 of 2");
    });

    // ADR-044 K5 at the coarsest scale: a cluster nobody has reported on is not
    // a clean cluster, and a summary of an empty inventory would say it was.
    it("leads with agent setup when nothing has ever reported", () => {
        const clusterLastSeen = cluster.last_seen_at;
        cluster.last_seen_at = "";
        try {
            const { container } = renderPage([], EMPTY, []);

            expect(container.textContent).toContain("No agent has reported yet");
            expect(container.textContent).toContain("not the same as a cluster running nothing");
            // The command carries the cluster's own id, so there is nothing to
            // transcribe out of the URL.
            const commands = must(container.querySelector(".agent-setup-commands"), "commands");
            expect(commands.textContent).toContain("--set cluster.id=c-prod");
            // And none of the cards that would summarise an inventory it does
            // not have.
            expect(container.querySelector(".overview-vuln-list")).toBeNull();
            expect(container.textContent).not.toContain("There is nothing to ingest");
        } finally {
            cluster.last_seen_at = clusterLastSeen;
        }
    });

    // A tab in the URL is what makes a filtered view something you can paste
    // into an issue.
    it("renders the tab named in the search param", () => {
        searchParams = { tab: "workloads", group: "workload" };
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
        searchParams = { tab: "workloads", group: "workload", match_state: "bogus" };
        renderPage([workload()], GAPPY);

        expect(lastWorkloadParams?.match_state).toBeUndefined();
    });

    it("marks the tile whose rows are on screen", () => {
        searchParams = { tab: "workloads", match_state: "exact" };
        const { container } = renderPage([workload()], GAPPY);

        const tiles = [...container.querySelectorAll(".coverage-tile")];
        expect(must(tiles[1], "matched tile").className).toContain("active");
        expect(must(tiles[0], "containers tile").className).not.toContain("active");
    });

    it("labels every match state in words, not colour alone", () => {
        const states = [
            ["exact", "matched"],
            ["index", "index match"],
            ["unknown", "no SBOM"],
            ["unresolvable", "no digest"],
        ] as const;
        for (const [state, label] of states) {
            searchParams = { tab: "workloads", group: "workload" };
            const { container, unmount } = renderPage([workload({ match_state: state })], {
                total: 1,
                matched: state === "exact" || state === "index" ? 1 : 0,
                unknown: state === "unknown" ? 1 : 0,
                unresolvable: state === "unresolvable" ? 1 : 0,
                pods: 1,
            });
            const row = must(container.querySelector("tbody tr"), "workload row");
            expect(row.textContent).toContain(label);
            unmount();
        }
    });

    it("links a matched workload to its artifact and SBOM", () => {
        searchParams = { tab: "workloads", group: "workload" };
        const { container } = renderPage([workload()], GAPPY);

        const row = must(container.querySelector("tbody tr"), "workload row");
        const hrefs = [...row.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(hrefs).toContain("/artifacts/a-1");
        expect(hrefs).toContain("/sboms/s-1");
    });

    // The whole point of the vulnerability column: "which of these images have
    // vulnerabilities" must be answerable from the table itself.
    it("shows per-severity findings on a matched workload", () => {
        searchParams = { tab: "workloads", group: "workload" };
        const { container } = renderPage(
            [workload({ vulns: { critical: 2, high: 1, medium: 0, low: 4 } })],
            GAPPY,
        );

        const row = must(container.querySelector("tbody tr"), "workload row");
        const chip = must(row.querySelector(".vuln-chip"), "severity chip");
        expect(chip.getAttribute("title")).toContain("2 critical");
        expect(chip.getAttribute("title")).toContain("1 high");
        expect(chip.getAttribute("title")).toContain("4 low");
    });

    // ADR-044 K5 in a single cell. An image nobody assessed and an image
    // assessed with nothing wrong are different facts, and the table is where
    // they are most easily confused into one clean-looking dash.
    it("distinguishes an unassessed image from an assessed clean one", () => {
        searchParams = { tab: "workloads", group: "workload" };
        const { container, unmount } = renderPage(
            [workload({ match_state: "unknown", artifact_id: undefined, sbom_id: undefined })],
            GAPPY,
        );
        expect(must(container.querySelector("tbody tr"), "row").textContent).toContain(
            "not assessed",
        );
        unmount();

        searchParams = { tab: "workloads", group: "workload" };
        const clean = renderPage(
            [workload({ vulns: { critical: 0, high: 0, medium: 0, low: 0 } })],
            GAPPY,
        );
        const cleanRow = must(clean.container.querySelector("tbody tr"), "row");
        expect(cleanRow.textContent).toContain("no findings");
        expect(cleanRow.textContent).not.toContain("not assessed");
    });

    // Filters must reach the server, not just the rows already fetched — the
    // list is paginated, so filtering the current page would be a lie.
    it("passes the filter and sort params through to the query", () => {
        searchParams = {
            tab: "workloads",
            group: "workload",
            k8s_namespace: "kube-system",
            match_state: "unknown",
            q: "redis",
            sort: "vuln_count",
            dir: "desc",
            offset: "50",
        };
        renderPage([workload()], GAPPY);

        expect(lastWorkloadParams).toMatchObject({
            k8s_namespace: "kube-system",
            match_state: "unknown",
            q: "redis",
            sort: "vuln_count",
            dir: "desc",
            offset: 50,
        });
    });

    // A sort key the API does not define would otherwise reach a SQL CASE that
    // matches no branch, producing an arbitrary order that looks like a sort.
    it("ignores a sort key the API does not define", () => {
        searchParams = { tab: "workloads", group: "workload", sort: "whatever", dir: "sideways" };
        renderPage([workload()], GAPPY);

        expect(lastWorkloadParams?.sort).toBe("vuln_count");
        expect(lastWorkloadParams?.dir).toBe("desc");
    });

    // Page 4 of the old result set is a meaningless place to land in the new
    // one, so any filter or sort change has to clear the offset.
    it("resets paging when a filter or sort changes", () => {
        searchParams = { tab: "workloads", offset: "50" };
        const { container } = renderPage([workload()], GAPPY);

        const selects = [...container.querySelectorAll(".search-bar select")];
        const namespaceSelect = must(selects[0], "namespace select") as HTMLSelectElement;
        namespaceSelect.value = "kube-system";
        namespaceSelect.dispatchEvent(new Event("change", { bubbles: true }));

        const filterWrite = lastWrite();
        expect(filterWrite.k8s_namespace).toBe("kube-system");
        // The key must be *present* and undefined — an absent key would leave
        // the stale offset in the URL rather than clearing it.
        expect("offset" in filterWrite).toBe(true);
        expect(filterWrite.offset).toBeUndefined();

        const header = must(
            [...container.querySelectorAll("th")].find((th) =>
                th.textContent.includes("Vulnerabilities"),
            ),
            "vulnerabilities header",
        );
        must(header.querySelector("button") ?? header, "sortable header").dispatchEvent(
            new MouseEvent("click", { bubbles: true }),
        );

        const sortWrite = lastWrite();
        expect(sortWrite.sort).toBe("vuln_count");
        expect("offset" in sortWrite).toBe(true);
        expect(sortWrite.offset).toBeUndefined();
    });

    // The facet query describes the whole cluster; options built from the rows
    // on screen would silently omit every namespace off the current page.
    it("offers namespaces the current page does not contain", () => {
        searchParams = { tab: "workloads" };
        const { container } = renderPage([workload({ k8s_namespace: "default" })], GAPPY);

        const namespaceSelect = must(
            container.querySelector(".search-bar select"),
            "namespace select",
        );
        expect(namespaceSelect.textContent).toContain("kube-system");
        expect(namespaceSelect.textContent).toContain("(3)");
    });

    // ---------------------------------------------------------------------
    // Grouping (ocidex-9do0.5)
    //
    // R3: one image rolled out across fourteen deployments used to be fourteen
    // near-identical rows, sorted alphabetically by namespace. An image is the
    // unit of the remedy, so it is the default unit of the table.
    // ---------------------------------------------------------------------

    it("groups by image by default", () => {
        searchParams = { tab: "workloads" };
        const { container } = renderPage([workload()], GAPPY);

        const row = must(container.querySelector("tbody tr"), "image row");
        // The counts the grouping folded away have to stay on screen, or the
        // row understates how much of the cluster one ingest would cover.
        expect(row.textContent).toContain("4");
        expect(row.textContent).toContain("12");
        expect(row.textContent).toContain("default/api");
        // The by-workload identity columns are gone in this grouping.
        const headers = [...container.querySelectorAll("th")].map((th) => th.textContent);
        expect(headers).toContain("Workloads");
        expect(headers).not.toContain("Container");
    });

    it("opens on the worst findings rather than the first namespace alphabetically", () => {
        searchParams = { tab: "workloads" };
        renderPage([workload()], GAPPY);

        expect(lastImageParams?.sort).toBe("vuln_count");
        expect(lastImageParams?.dir).toBe("desc");
    });

    it("keeps the filters when the grouping changes", () => {
        searchParams = { tab: "workloads", k8s_namespace: "kube-system", q: "redis" };
        const { container } = renderPage([workload()], GAPPY);

        const select = must(
            container.querySelector('[data-testid="grouping-select"]'),
            "grouping select",
        ) as HTMLSelectElement;
        select.value = "workload";
        select.dispatchEvent(new Event("change", { bubbles: true }));

        const write = lastWrite();
        expect(write.group).toBe("workload");
        // Sort and offset are dropped, not kept: the key the reader was sorted
        // on may not exist as a column in the other grouping, and page 4 of the
        // old result set is a meaningless place to land in the new one.
        expect("sort" in write).toBe(true);
        expect(write.sort).toBeUndefined();
        expect(write.offset).toBeUndefined();
        // The narrowing itself survives: the write does not mention those keys
        // at all, so the merge leaves them in the URL.
        expect("k8s_namespace" in write).toBe(false);
        expect("q" in write).toBe(false);
    });

    // A URL can name a sort key from the other grouping; the image list has no
    // namespace column to order by, and the SQL CASE it would reach matches no
    // branch, producing an arbitrary order that looks like a sort.
    it("drops a sort key that only the other grouping has", () => {
        searchParams = { tab: "workloads", sort: "k8s_namespace", dir: "asc" };
        renderPage([workload()], GAPPY);

        expect(lastImageParams?.sort).toBe("vuln_count");
    });

    // ADR-044 K5 holds in both groupings or it holds in neither: the same cell
    // renders the three outcomes, and this is the half that the by-image view
    // would otherwise be free to get wrong.
    it("distinguishes an unassessed image from an assessed clean one by image", () => {
        searchParams = { tab: "workloads" };
        const { container, unmount } = renderPage([workload()], GAPPY, [], [
            image({ match_state: "unknown", artifact_id: undefined, sbom_id: undefined }),
        ]);
        const row = must(container.querySelector("tbody tr"), "image row");
        expect(row.textContent).toContain("not assessed");
        expect(row.textContent).toContain("no SBOM");
        unmount();

        searchParams = { tab: "workloads" };
        const clean = renderPage([workload()], GAPPY, [], [
            image({ vulns: { critical: 0, high: 0, medium: 0, low: 0 } }),
        ]);
        const cleanRow = must(clean.container.querySelector("tbody tr"), "image row");
        expect(cleanRow.textContent).toContain("no findings");
        expect(cleanRow.textContent).not.toContain("not assessed");
    });

    it("links an image row to the artifact and SBOM behind it", () => {
        searchParams = { tab: "workloads" };
        const { container } = renderPage([workload()], GAPPY);

        const row = must(container.querySelector("tbody tr"), "image row");
        const hrefs = [...row.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(hrefs).toContain("/artifacts/a-1");
        expect(hrefs).toContain("/sboms/s-1");
    });

    // ---------------------------------------------------------------------
    // Vulnerabilities tab
    // ---------------------------------------------------------------------

    // The original page showed a bar of counts with nothing behind it. The
    // point of the tab is that every number is a row you can open.
    it("lists running vulnerabilities with a severity strip", () => {
        searchParams = { tab: "vulnerabilities" };
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        expect(container.textContent).toContain("CVE-2026-1000");
        expect(container.textContent).toContain("Remote code execution");

        const severityTabs = [...container.querySelectorAll(".filter-chips button")].map(
            (b) => b.textContent,
        );
        expect(severityTabs).toContain("CRITICAL");
        expect(severityTabs).toContain("LOW");
    });

    // A severity strip that filtered client-side would filter one page and
    // call it the answer; the choice has to reach the query.
    it("sends the severity filter and sort to the server", () => {
        searchParams = {
            tab: "vulnerabilities",
            severity: "HIGH",
            sort: "workload_count",
            dir: "asc",
        };
        renderPage([workload()], GAPPY, [vuln()]);

        expect(lastVulnParams?.severity).toBe("HIGH");
        expect(lastVulnParams?.sort).toBe("workload_count");
        expect(lastVulnParams?.dir).toBe("asc");
    });

    // Same reasoning as the workload table: an unrecognised key would reach the
    // SQL CASE and produce an arbitrary order that looks like a working sort.
    it("ignores a sort key the API does not accept", () => {
        searchParams = { tab: "vulnerabilities", sort: "blast_radius", severity: "SPICY" };
        renderPage([workload()], GAPPY, [vuln()]);

        expect(lastVulnParams?.sort).toBe("severity");
        expect(lastVulnParams?.severity).toBeUndefined();
    });

    // "3 workloads" is not actionable until you can see which three, and the
    // list must not be fetched for every row of the page up front.
    it("fetches the workloads behind a count only once the row is opened", async () => {
        searchParams = { tab: "vulnerabilities" };
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        const toggle = must(
            container.querySelector(".link-button"),
            "workload-count toggle",
        ) as HTMLButtonElement;
        expect(toggle.getAttribute("aria-expanded")).toBe("false");
        expect(lastVulnWorkloadArgs?.options?.().enabled).toBe(false);
        expect(container.textContent).not.toContain("checkout");

        toggle.click();
        await Promise.resolve();

        expect(toggle.getAttribute("aria-expanded")).toBe("true");
        expect(lastVulnWorkloadArgs?.options?.().enabled).toBe(true);
        // Scoped to this cluster: the same advisory elsewhere is a different
        // question, asked on the vulnerability page.
        expect(lastVulnWorkloadArgs?.clusterId?.()).toBe("c-prod");
        expect(container.textContent).toContain("checkout");
        expect(container.textContent).toContain("payments");
    });

    // Counts with no denominator are the failure ADR-044 K5 names: rows the
    // cluster could not assess must be stated wherever findings are.
    it("names the containers this list could not assess", () => {
        searchParams = { tab: "vulnerabilities" };
        const { container } = renderPage([workload()], GAPPY, [vuln()]);

        const caveat = must(container.querySelector(".coverage-caveat"), "coverage caveat");
        expect(caveat.textContent).toContain("6 running containers");
        expect(caveat.textContent).toContain("unknown, not zero");
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

    // Twelve replicas of one unscanned image are one thing to ingest. Listing
    // them per container would make the gap look twelve times larger and give
    // twelve copies of the same action.
    it("lists the No-SBOM gap by image, not by container", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [unknownImage({ workload_count: 3, pod_count: 9 })];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("ghcr.io/pfenerty/api:v1");
        expect(container.textContent).toContain("and 2 other containers");
        expect(container.textContent).toContain("9");
    });

    // The whole point of the tab: every row says what stands between this image
    // and an SBOM, and each answer is a different thing to go and do.
    it("names the remedy for each unresolved image", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [
            unknownImage({ image_ref: "ghcr.io/a:v1", reason: "ready", registry_id: "r-1", registry_name: "ghcr" }),
            unknownImage({ image_ref: "gcr.io/b:v1", reason: "no_registry", registry_host: "gcr.io" }),
            unknownImage({ image_ref: "quay.io/c:v1", reason: "registry_disabled", registry_id: "r-2", registry_name: "quay" }),
            unknownImage({ image_ref: "quay.io/d:v1", reason: "pattern_excluded", registry_id: "r-2", registry_name: "quay" }),
        ];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("ready to ingest");
        expect(container.textContent).toContain("no registry");
        expect(container.textContent).toContain("gcr.io");
        // "switched off" and "never configured" are different problems, so the
        // matched registry is named rather than reported as absent.
        expect(container.textContent).toContain("registry disabled");
        expect(container.textContent).toContain("excluded by patterns");
        expect(container.textContent).toContain("quay");

        // Both links used to point at a top-level /registries route that has
        // never existed in App.tsx, so a tab whose whole job is naming the
        // remedy sent the reader to a 404. Registries are managed on the
        // Sources tab; the host travels with the link so the add dialog opens
        // knowing what it is being added for.
        const addRegistry = [...container.querySelectorAll("a")].find(
            (a) => a.textContent === "add a registry",
        );
        expect(addRegistry?.getAttribute("href")).toBe("/admin/sources?add=1&host=gcr.io");
        const named = [...container.querySelectorAll("a")].find(
            (a) => a.getAttribute("href") === "/admin/sources?registry=r-2",
        );
        expect(named).toBeDefined();
    });

    // A gap that cannot be ingested must not be counted as work the existing
    // registries can absorb.
    it("counts only the images the namespace's registries can serve", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [
            unknownImage({ image_ref: "ghcr.io/a:v1", reason: "ready" }),
            unknownImage({ image_ref: "gcr.io/b:v1", reason: "no_registry" }),
            unknownImage({ image_ref: "gcr.io/c:v1", reason: "no_registry" }),
        ];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("1 of 3 images can be ingested");
    });

    // The gap is only actionable if the action is on the page. The bulk button
    // ingests the whole gap, so it names the count it will actually queue
    // rather than the size of the gap.
    it("offers a bulk ingest sized to what can actually be ingested", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [
            unknownImage({ image_ref: "ghcr.io/a:v1", reason: "ready" }),
            unknownImage({ image_ref: "ghcr.io/b:v1", reason: "ready" }),
            unknownImage({ image_ref: "gcr.io/c:v1", reason: "no_registry" }),
        ];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        const bulk = [...container.querySelectorAll("button")].find((b) =>
            b.textContent.startsWith("Ingest 2 images"),
        );
        must(bulk, "the bulk ingest button").click();

        // No digests: the whole gap, which is what the button says.
        expect(ingestCalls).toEqual([{ id: "c-prod", imageDigests: undefined }]);
    });

    // A per-row button that queued the whole cluster would be lying about what
    // it points at, so it names its own digest.
    it("ingests one image from its own row", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [
            unknownImage({ image_ref: "ghcr.io/a:v1", image_digest: "sha256:aaa", reason: "ready" }),
            unknownImage({ image_ref: "ghcr.io/b:v1", image_digest: "sha256:bbb", reason: "ready" }),
        ];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        const rowButtons = [...container.querySelectorAll("button")].filter(
            (b) => b.textContent === "Ingest",
        );
        expect(rowButtons).toHaveLength(2);
        must(rowButtons[1], "the second row's ingest button").click();

        expect(ingestCalls).toEqual([{ id: "c-prod", imageDigests: ["sha256:bbb"] }]);
    });

    // A row that cannot be ingested must not offer a button that would do
    // nothing — the reason is the remedy there, not the action.
    it("offers no row action for an image no registry can serve", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [unknownImage({ reason: "no_registry" })];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        const rowButtons = [...container.querySelectorAll("button")].filter(
            (b) => b.textContent === "Ingest",
        );
        expect(rowButtons).toHaveLength(0);
    });

    // Queueing is not scanning, and a skip is not a failure. The result names
    // every reason so "queued 1 of 3" is never left to be read as an error.
    it("reports queued and skipped counts separately after a run", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [unknownImage()];
        ingestResult = {
            considered: 3,
            queued: 1,
            skipped_no_registry: 1,
            skipped_registry_disabled: 0,
            skipped_pattern_excluded: 1,
            skipped_unparseable_ref: 0,
            failed: 0,
        };
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("Queued 1 scan job");
        expect(container.textContent).toContain("1 skipped: no registry configured");
        expect(container.textContent).toContain("1 skipped: excluded by registry patterns");
        expect(container.textContent).not.toContain("registry disabled");
        expect(container.textContent).toContain("in the background");
    });

    // Overview has to say whether the gap is closing on its own. Without this
    // the only way to know is to read the cluster list.
    it("states on the overview whether auto-ingest is closing the gap", () => {
        unknownImages = [
            unknownImage({ image_ref: "ghcr.io/a:v1", reason: "ready" }),
            unknownImage({ image_ref: "gcr.io/b:v1", reason: "no_registry" }),
        ];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("Auto-ingest is");
        expect(container.textContent).toContain("on");
        expect(container.textContent).toContain("1 image can be ingested now");
        expect(container.textContent).toContain("1 cannot");
    });

    // Both Gaps tables asked for 200 rows and rendered no pager, so a bigger
    // cluster showed a short list with nothing saying it was short. Every
    // figure on the tab now comes from the server's tally of the whole gap.
    it("describes the whole gap rather than the page it was handed", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [unknownImage({ image_ref: "ghcr.io/a:v1", reason: "ready" })];
        unknownGap = { total: 412, reasons: { ...NO_REASONS, ready: 300, no_registry: 112 } };
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("300 of 412 images can be ingested");
        // The bulk button ingests the whole gap, so it must name the whole
        // gap: sized off the page it would have promised one job and queued
        // three hundred.
        const bulk = [...container.querySelectorAll("button")].find((b) =>
            b.textContent.startsWith("Ingest "),
        );
        expect(bulk?.textContent).toBe("Ingest 300 images");
    });

    it("pages the gap instead of stopping at the end of the first screen", () => {
        searchParams = { tab: "gaps" };
        unknownImages = [unknownImage({ image_ref: "ghcr.io/a:v1" })];
        unknownGap = { total: 412, reasons: { ...NO_REASONS, ready: 412 } };
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        // Two pagers: one per table. Their presence is the fix — a table that
        // holds one page of 412 with no pager is the silent truncation.
        expect(container.querySelectorAll(".pagination").length).toBe(2);
    });

    // The overview line is a summary of the gap, so it must not be a summary of
    // whatever page the shared query happened to hold.
    it("counts the overview's ready and blocked images across the whole gap", () => {
        unknownImages = [unknownImage({ reason: "ready" })];
        unknownGap = { total: 412, reasons: { ...NO_REASONS, ready: 300, no_registry: 112 } };
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("300 images can be ingested now");
        expect(container.textContent).toContain("112 cannot");
    });

    it("says so on the overview when auto-ingest is off", () => {
        autoIngest = false;
        unknownImages = [unknownImage({ reason: "ready" })];
        const { container } = renderPage([workload({ match_state: "unknown" })], GAPPY);

        expect(container.textContent).toContain("off");
        expect(container.textContent).toContain("stays unscanned");
    });

    // Nothing to ingest is its own state: an ingest card offering a run over an
    // empty gap reads as unfinished work that does not exist.
    it("says there is nothing to ingest when every digest matched", () => {
        const { container } = renderPage([workload()], {
            total: 4,
            matched: 4,
            unknown: 0,
            unresolvable: 0,
            pods: 9,
        });

        expect(container.textContent).toContain("There is nothing to ingest");
    });
});
