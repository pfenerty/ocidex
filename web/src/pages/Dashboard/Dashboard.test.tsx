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

beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useAuth).mockReturnValue({
        user: (() => ({ id: "u1", github_username: "octocat", role: "member" })) as unknown as ReturnType<
            typeof useAuth
        >["user"],
        refetch: vi.fn(),
    });
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
