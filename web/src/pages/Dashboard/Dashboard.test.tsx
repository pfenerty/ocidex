// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import {
    useMyNamespaces,
    useMyActivity,
    useMyDriftFeed,
    useMyVulnerabilities,
    useMyClusters,
    useWatchFeed,
} from "~/api/queries";
import { useAuth } from "~/context/auth";
import Dashboard from "./index";

vi.mock("~/api/queries", () => ({
    useMyNamespaces: vi.fn(),
    useMyActivity: vi.fn(),
    useMyDriftFeed: vi.fn(),
    useMyVulnerabilities: vi.fn(),
    useMyClusters: vi.fn(),
    // ClustersPanel borrows StalenessPill from the Clusters page, whose module
    // imports these at load time.
    useListClusters: vi.fn(),
    useCreateCluster: vi.fn(),
    useUpdateCluster: vi.fn(),
    useDeleteCluster: vi.fn(),
    useWatchFeed: vi.fn(),
}));

vi.mock("~/context/auth", () => ({ useAuth: vi.fn() }));

// The router stub forwards href so the "links to its detail view" assertions
// can read it; a stub that dropped it would make every one of them vacuous.
vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; class?: string; children?: JSX.Element }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

interface Query {
    isLoading: boolean;
    isError: boolean;
    error?: unknown;
    data: { data: unknown[] } | undefined;
}

const loaded = (rows: unknown[]): Query => ({
    isLoading: false,
    isError: false,
    error: undefined,
    data: { data: rows },
});

const loading: Query = { isLoading: true, isError: false, error: undefined, data: undefined };

const mocks = {
    namespaces: vi.mocked(useMyNamespaces),
    activity: vi.mocked(useMyActivity),
    drift: vi.mocked(useMyDriftFeed),
    vulns: vi.mocked(useMyVulnerabilities),
    clusters: vi.mocked(useMyClusters),
    watchFeed: vi.mocked(useWatchFeed),
};

// The hooks return as many different row types as there are panels, so one loop
// cannot name a single ReturnType that satisfies them all. `never` is assignable
// to every one of them, which is exactly the "this stub is deliberately
// untyped" claim.
function setAll(query: Query) {
    for (const m of Object.values(mocks)) {
        m.mockReturnValue(query as never);
    }
}

/**
 * Sign the mocked auth context in, optionally with namespace memberships. No
 * memberships is the ordinary case and the one every pre-existing test here
 * runs under: it produces the "balanced" emphasis, which is the ordering the
 * page shipped with.
 */
function signedInAs(...roles: string[]) {
    const memberships = roles.map((role, i) => ({ namespace_id: `n${String(i)}`, role }));
    vi.mocked(useAuth).mockReturnValue({
        user: (() => ({
            id: "u1",
            github_username: "octocat",
            role: "member",
            memberships,
        })) as unknown as ReturnType<typeof useAuth>["user"],
        refetch: vi.fn(),
    });
}

beforeEach(() => {
    vi.clearAllMocks();
    signedInAs();
    setAll(loaded([]));
});

describe("Dashboard", () => {
    it("renders every section, so a new panel cannot silently go missing", () => {
        const { getByText } = render(() => <Dashboard />);
        for (const heading of [
            "My namespaces",
            "Ingest activity",
            "Provenance drift",
            "Vulnerability exposure",
            "My clusters",
            "Watched artifacts",
        ]) {
            expect(getByText(heading)).toBeDefined();
        }
    });

    it("greets the signed-in user", () => {
        const { getByText } = render(() => <Dashboard />);
        expect(getByText("Signed in as octocat")).toBeDefined();
    });

    it("shows a per-panel empty message rather than an endless skeleton", () => {
        const { getByText } = render(() => <Dashboard />);
        expect(getByText("You do not own any namespaces yet.")).toBeDefined();
        expect(getByText("No provenance drift on your artifacts.")).toBeDefined();
        expect(getByText("No known vulnerabilities in what you own.")).toBeDefined();
        expect(
            getByText("No clusters registered. Register one to see what your clusters actually run."),
        ).toBeDefined();
    });

    it("links each row to the page that owns it", () => {
        mocks.namespaces.mockReturnValue(
            loaded([
                { id: "n1", name: "workspace-ns", visibility: "private", created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
            ]) as unknown as ReturnType<typeof useMyNamespaces>,
        );
        mocks.activity.mockReturnValue(
            loaded([
                {
                    sbomId: "s1",
                    artifactName: "ubuntu",
                    namespaceId: "n1",
                    namespaceName: "prod",
                    createdAt: new Date().toISOString(),
                },
            ]) as unknown as ReturnType<typeof useMyActivity>,
        );
        mocks.drift.mockReturnValue(
            loaded([
                {
                    sbomId: "s2",
                    artifactName: "alpine",
                    previousStatus: "verified",
                    newStatus: "unsigned",
                    reason: "reverification_failed",
                    detectedAt: new Date().toISOString(),
                },
            ]) as unknown as ReturnType<typeof useMyDriftFeed>,
        );
        mocks.vulns.mockReturnValue(
            loaded([
                {
                    id: "CVE-2099-0001",
                    canonicalId: "CVE-2099-0001",
                    severity: "HIGH",
                    aliases: null,
                    affectedSbomCount: 3,
                    affectedPurlCount: 1,
                },
            ]) as unknown as ReturnType<typeof useMyVulnerabilities>,
        );
        mocks.clusters.mockReturnValue(
            loaded([
                {
                    id: "c1",
                    name: "prod-eu-west",
                    namespace_id: "n1",
                    namespace_name: "prod",
                    last_seen_at: new Date().toISOString(),
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString(),
                },
            ]) as unknown as ReturnType<typeof useMyClusters>,
        );

        const { getByText } = render(() => <Dashboard />);
        expect(getByText("workspace-ns").closest("a")?.getAttribute("href")).toBe("/admin/namespaces");
        expect(getByText("prod-eu-west").closest("a")?.getAttribute("href")).toBe("/clusters/c1");
        expect(getByText("ubuntu").closest("a")?.getAttribute("href")).toBe("/sboms/s1");
        expect(getByText("alpine").closest("a")?.getAttribute("href")).toBe("/sboms/s2");
        expect(getByText("CVE-2099-0001").closest("a")?.getAttribute("href")).toBe(
            "/vulnerabilities/CVE-2099-0001",
        );
    });

    // Every panel used to render with identical weight, so a provenance
    // regression read exactly like a list of namespaces (ocidex-ag4q.40).
    describe("panel severity", () => {
        it("marks an alarm panel raised only when it has something to report", () => {
            mocks.drift.mockReturnValue(
                loaded([
                    {
                        sbomId: "s2",
                        artifactName: "alpine",
                        previousStatus: "verified",
                        newStatus: "unsigned",
                        reason: "reverification_failed",
                        detectedAt: new Date().toISOString(),
                    },
                ]) as unknown as ReturnType<typeof useMyDriftFeed>,
            );

            const { container } = render(() => <Dashboard />);
            const drift = container.querySelector('[data-section="drift"]');
            const exposure = container.querySelector('[data-section="exposure"]');
            expect(drift?.querySelector(".dash-panel-alert")).not.toBeNull();
            // Exposure came back empty, so it stays quiet.
            expect(exposure?.querySelector(".dash-panel-alert")).toBeNull();
            // Inventory panels never carry alert weight, full or empty.
            expect(container.querySelector('[data-section="namespaces"] .dash-panel-alert')).toBeNull();
        });

        it("holds an in-flight alarm panel in the pending state", () => {
            setAll(loading);
            const { container } = render(() => <Dashboard />);
            const drift = container.querySelector('[data-section="drift"]');
            // Not "clear": a panel that is about to raise must not sink to the
            // bottom of the grid and jump back up when its rows arrive.
            expect(drift?.querySelector(".dash-panel-pending")).not.toBeNull();
            expect(drift?.querySelector(".dash-panel-alert")).toBeNull();
        });

        it("orders the alarm sections ahead of the inventory", () => {
            const { container } = render(() => <Dashboard />);
            const ids = [...container.querySelectorAll("[data-section]")].map((el) =>
                el.getAttribute("data-section"),
            );
            expect(ids.slice(0, 2)).toEqual(["drift", "exposure"]);
            // The tone is on the wrapper, which is what Dashboard.css uses to
            // sink an alarm section that has come back clear.
            expect(ids.length).toBe(6);
            expect(
                container.querySelector('[data-section="drift"]')?.classList.contains("dash-section-alert"),
            ).toBe(true);
            expect(
                container
                    .querySelector('[data-section="namespaces"]')
                    ?.classList.contains("dash-section-inventory"),
            ).toBe(true);
        });
    });

    describe("role emphasis", () => {
        const sectionIDs = (container: HTMLElement) =>
            [...container.querySelectorAll("[data-section]")].map((el) => el.getAttribute("data-section"));

        it("leads a mostly-security caller with what is wrong", () => {
            signedInAs("security", "security", "developer");
            const { container } = render(() => <Dashboard />);
            expect(sectionIDs(container).slice(0, 3)).toEqual(["drift", "exposure", "clusters"]);
        });

        it("leads a mostly-developer caller with what they just shipped", () => {
            signedInAs("developer", "developer", "security");
            const { container } = render(() => <Dashboard />);
            expect(sectionIDs(container).slice(0, 2)).toEqual(["ingest", "namespaces"]);
        });

        it("keeps the shipped ordering for an owner", () => {
            signedInAs("owner", "security");
            const { container } = render(() => <Dashboard />);
            expect(sectionIDs(container)).toEqual([
                "drift",
                "exposure",
                "namespaces",
                "ingest",
                "clusters",
                "watch-feed",
            ]);
        });

        // The point of the story, and the thing a reordering bug would break
        // silently: emphasis is a permutation of the panels, never a filter.
        // Hiding a panel a caller is allowed to see would make the page lie
        // about what they have access to.
        it("renders every section under every emphasis", () => {
            const all = ["drift", "exposure", "namespaces", "ingest", "clusters", "watch-feed"];
            for (const roles of [["security"], ["developer"], ["owner"], []]) {
                signedInAs(...roles);
                const { container, unmount } = render(() => <Dashboard />);
                expect([...sectionIDs(container)].sort()).toEqual([...all].sort());
                unmount();
            }
        });
    });

    // A repository that pushes on every commit filled all five visible slots
    // with itself, so the feed carried one fact five times.
    it("collapses the ingest feed to one row per artifact", () => {
        const at = (mins: number) => new Date(Date.now() - mins * 60_000).toISOString();
        mocks.activity.mockReturnValue(
            loaded([
                { sbomId: "s1", artifactId: "a1", artifactName: "ocidex", namespaceId: "n1", namespaceName: "prod", createdAt: at(1) },
                { sbomId: "s2", artifactId: "a1", artifactName: "ocidex", namespaceId: "n1", namespaceName: "prod", createdAt: at(5) },
                { sbomId: "s3", artifactId: "a1", artifactName: "ocidex", namespaceId: "n1", namespaceName: "prod", createdAt: at(9) },
                { sbomId: "s4", artifactId: "a2", artifactName: "tektonic", namespaceId: "n1", namespaceName: "prod", createdAt: at(20) },
            ]) as unknown as ReturnType<typeof useMyActivity>,
        );

        const { container, getByText } = render(() => <Dashboard />);
        const rows = [
            ...(container.querySelector('[data-section="ingest"]')?.querySelectorAll(".dash-row") ?? []),
        ];
        expect(rows.length).toBe(2);
        // The newest of the collapsed run is the one kept...
        expect(getByText("ocidex").closest("a")?.getAttribute("href")).toBe("/sboms/s1");
        // ...and the ones it hid are counted, not silently dropped.
        expect(getByText(/3 ingests/)).toBeDefined();
    });

    it("routes each watch-event kind to the page that explains it", () => {
        mocks.watchFeed.mockReturnValue(
            loaded([
                {
                    kind: "new_version",
                    id: "e1",
                    artifactId: "a1",
                    artifactName: "curl",
                    artifactType: "container",
                    sbomId: "s9",
                    version: "8.6.0",
                    previousVersion: "8.5.0",
                    occurredAt: new Date().toISOString(),
                },
                {
                    kind: "vulnerability",
                    id: "e2",
                    artifactId: "a1",
                    artifactName: "openssl",
                    artifactType: "container",
                    sbomId: "s9",
                    vulnerabilityId: "CVE-2099-0002",
                    severity: "CRITICAL",
                    occurredAt: new Date().toISOString(),
                },
            ]) as unknown as ReturnType<typeof useWatchFeed>,
        );

        const { getByText } = render(() => <Dashboard />);
        // A version event describes the step it represents, and lands on the SBOM.
        expect(getByText("new version 8.6.0 (was 8.5.0)")).toBeDefined();
        expect(getByText("curl").closest("a")?.getAttribute("href")).toBe("/sboms/s9");
        // A vulnerability event lands on the CVE, not on the SBOM.
        expect(getByText("openssl").closest("a")?.getAttribute("href")).toBe(
            "/vulnerabilities/CVE-2099-0002",
        );
    });

    it("shows a skeleton, not an empty message, while the first fetch is in flight", () => {
        setAll(loading);
        const { queryByText } = render(() => <Dashboard />);
        expect(queryByText("You do not own any namespaces yet.")).toBeNull();
    });
});
