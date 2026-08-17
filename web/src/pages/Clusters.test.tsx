// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import {
    useListClusters,
    useMyNamespaces,
    useCreateCluster,
    useUpdateCluster,
    useDeleteCluster,
} from "~/api/queries";
import Clusters from "~/pages/Clusters";

const createMutate = vi.fn();
const updateMutate = vi.fn();
const deleteMutate = vi.fn();

vi.mock("~/api/queries", () => ({
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
}));

const mockList = vi.mocked(useListClusters);
const mockNamespaces = vi.mocked(useMyNamespaces);
const mockCreate = vi.mocked(useCreateCluster);
const mockUpdate = vi.mocked(useUpdateCluster);
const mockDelete = vi.mocked(useDeleteCluster);

const prod = {
    id: "c-prod",
    name: "prod-eu-west",
    namespace_id: "ns-acme",
    namespace_name: "acme",
    description: "production",
    last_seen_at: new Date().toISOString(),
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
};

function mutation(mutate: ReturnType<typeof vi.fn>) {
    return (() => ({ mutate, isPending: false })) as never;
}

function renderPage(clusters: unknown[] = [prod]) {
    mockList.mockImplementation((() => ({
        data: { data: clusters },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockNamespaces.mockImplementation((() => ({
        data: { data: [{ id: "ns-acme", name: "acme" }] },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockCreate.mockImplementation(mutation(createMutate));
    mockUpdate.mockImplementation(mutation(updateMutate));
    mockDelete.mockImplementation(mutation(deleteMutate));
    return render(() => <Clusters />);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

function button(container: HTMLElement, label: string): HTMLButtonElement {
    const found = [...container.querySelectorAll("button")].find(
        (b) => b.textContent.trim() === label,
    );
    return must(found, `${label} button`);
}

describe("Clusters", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("lists each cluster with its namespace and links to its inventory", () => {
        const { container } = renderPage();

        const row = must(container.querySelector("tbody tr"), "cluster row");
        const cells = [...row.querySelectorAll("td")].map((c) => c.textContent.trim());
        expect(cells[0]).toBe("prod-eu-west");
        expect(cells[1]).toBe("acme");
        expect(cells[2]).toBe("production");
        expect(must(row.querySelector("a"), "detail link").getAttribute("href")).toBe(
            "/clusters/c-prod",
        );
    });

    // ADR-044 K5: a cluster that has never reported shows no workloads, which
    // must not be readable as "this cluster runs nothing".
    it("says so when a cluster has never reported", () => {
        const { container } = renderPage([{ ...prod, last_seen_at: "" }]);
        expect(container.textContent).toContain("never reported");
    });

    it("flags a cluster whose last snapshot is old as stale", () => {
        const { container } = renderPage([
            { ...prod, last_seen_at: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString() },
        ]);
        expect(container.textContent).toContain("stale");
    });

    it("does not call a fresh cluster stale", () => {
        const { container } = renderPage();
        expect(container.textContent).not.toContain("stale");
        expect(container.textContent).not.toContain("never reported");
    });

    it("registers a cluster in the chosen namespace", () => {
        const { container } = renderPage();

        const inputs = [...container.querySelectorAll("form input")];
        fireEvent.input(must(inputs[0], "name input"), { target: { value: "  staging  " } });
        fireEvent.change(must(container.querySelector("form select"), "namespace select"), {
            target: { value: "ns-acme" },
        });
        fireEvent.input(must(inputs[1], "description input"), { target: { value: "staging rig" } });
        fireEvent.submit(must(container.querySelector("form"), "create form"));

        expect(createMutate).toHaveBeenCalledTimes(1);
        expect(createMutate.mock.calls[0][0]).toEqual({
            namespace_id: "ns-acme",
            name: "staging",
            description: "staging rig",
        });
    });

    it("does not submit without a namespace", () => {
        const { container } = renderPage();
        fireEvent.input(must(container.querySelector("form input"), "name input"), {
            target: { value: "staging" },
        });
        fireEvent.submit(must(container.querySelector("form"), "create form"));
        expect(createMutate).not.toHaveBeenCalled();
    });

    it("renames a cluster inline", () => {
        const { container } = renderPage();

        fireEvent.click(button(container, "Edit"));
        fireEvent.input(
            must(container.querySelector('[data-testid="edit-name"]'), "inline name input"),
            { target: { value: "prod-eu-west-1" } },
        );
        fireEvent.click(button(container, "Save"));

        expect(updateMutate.mock.calls[0][0]).toEqual({
            id: "c-prod",
            name: "prod-eu-west-1",
            description: "production",
        });
    });

    it("only deletes on confirm", () => {
        const confirmSpy = vi.fn((_message?: string) => false);
        vi.stubGlobal("confirm", confirmSpy);
        const { container } = renderPage();

        fireEvent.click(button(container, "Delete"));
        expect(deleteMutate).not.toHaveBeenCalled();
        expect(confirmSpy.mock.calls[0][0]).toContain("recorded inventory");

        confirmSpy.mockReturnValue(true);
        fireEvent.click(button(container, "Delete"));
        expect(deleteMutate).toHaveBeenCalledWith("c-prod", expect.anything());
    });
});
