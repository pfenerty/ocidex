// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { useListClusters } from "~/api/queries";
import Clusters from "~/pages/Clusters";

vi.mock("~/api/queries", () => ({
    useListClusters: vi.fn(),
}));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

const mockList = vi.mocked(useListClusters);

const prod = {
    id: "c-prod",
    name: "prod-eu-west",
    namespaceId: "ns-acme",
    namespaceName: "acme",
    description: "production",
    autoIngest: true,
    lastSeenAt: new Date().toISOString(),
    health: { state: "healthy" },
    agent: { version: "v1.2.0", kubernetesVersion: "v1.33.1" },
    summary: {
        coverage: { total: 10, matched: 8, unknown: 1, unresolvable: 1, pods: 20 },
        runningCriticals: 3,
    },
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
};

function renderPage(clusters: unknown[] = [prod]) {
    mockList.mockImplementation((() => ({
        data: { data: clusters },
        isFetching: false,
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    return render(() => <Clusters />);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

function rowNames(container: HTMLElement): string[] {
    return [...container.querySelectorAll("tbody tr")].map(
        (r) => r.querySelector("a")?.textContent ?? "",
    );
}

describe("Clusters", () => {
    beforeEach(() => vi.clearAllMocks());

    it("lists each cluster with its namespace and links to its inventory", () => {
        const { container } = renderPage();
        const row = must(container.querySelector("tbody tr"), "cluster row");
        expect(row.textContent).toContain("prod-eu-west");
        expect(row.textContent).toContain("acme");
        expect(must(row.querySelector("a"), "detail link").getAttribute("href")).toBe("/clusters/c-prod");
    });

    // ocidex-70eo.7: each row answers "is this cluster OK?" on its own.
    it("shows coverage, running criticals and the agent version per row", () => {
        const { container } = renderPage();
        const row = must(container.querySelector("tbody tr"), "row");
        expect(row.textContent).toContain("80% matched");
        expect(row.textContent).toContain("3");
        expect(row.textContent).toContain("v1.2.0");
        expect(row.textContent).toContain("k8s v1.33.1");
        expect(must(row.querySelector(".coverage-bar"), "bar").getAttribute("aria-label")).toBe("80% matched");
    });

    // ADR-044 K5: a cluster that has never reported shows no workloads, which
    // must not be readable as "this cluster runs nothing".
    it("says so when a cluster has never reported, and offers to finish connecting", () => {
        const { container } = renderPage([
            { ...prod, lastSeenAt: "", health: { state: "never_reported" }, summary: undefined, agent: undefined },
        ]);
        expect(container.textContent).toContain("Never reported");
        expect(container.textContent).toContain("finish connecting");
        expect(container.textContent).not.toContain("% matched");
    });

    it("shows an erroring agent with the server's reason in the row", () => {
        const { container } = renderPage([
            { ...prod, health: { state: "erroring", reason: "The agent's API key was not accepted" } },
        ]);
        const pill = [...container.querySelectorAll(".status-chip")].find((b) => b.textContent.startsWith("Erroring"));
        expect(pill?.getAttribute("title")).toBe("The agent's API key was not accepted");
        expect(container.textContent).toContain("The agent's API key was not accepted");
    });

    it("trusts the server's stale verdict over the client's hour", () => {
        const { container } = renderPage([{ ...prod, health: { state: "stale", reason: "No snapshot for 16m" } }]);
        expect(container.textContent).toContain("Stale");
    });

    it("does not call a fresh cluster stale", () => {
        const { container } = renderPage();
        expect(container.textContent).not.toContain("Stale");
        expect(container.textContent).not.toContain("Never reported");
    });

    it("puts problems first", () => {
        const { container } = renderPage([
            { ...prod, id: "a", name: "a-healthy" },
            { ...prod, id: "b", name: "b-stale", health: { state: "stale", reason: "x" } },
            { ...prod, id: "c", name: "c-erroring", health: { state: "erroring", reason: "x" } },
        ]);
        expect(rowNames(container)).toEqual(["c-erroring", "b-stale", "a-healthy"]);
    });

    it("flags version skew", () => {
        const { container } = renderPage([
            { ...prod, agent: { ...prod.agent, versionSkew: "agent v1.0.0 is older than server v1.2.0" } },
        ]);
        const pill = [...container.querySelectorAll(".badge")].find((b) => b.textContent === "skew");
        expect(pill?.getAttribute("title")).toContain("older than server");
    });

    // ocidex-70eo.6/.7: connecting is its own page, and the list is read-only.
    it("links to the connect page and offers no inline editing", () => {
        const { container } = renderPage();
        const link = [...container.querySelectorAll("a")].find((a) => a.textContent.trim() === "Connect a cluster");
        expect(must(link, "connect link").getAttribute("href")).toBe("/clusters/new");
        expect(container.querySelector("form")).toBeNull();
        expect([...container.querySelectorAll("button")].map((b) => b.textContent.trim())).not.toContain("Edit");
    });
});
