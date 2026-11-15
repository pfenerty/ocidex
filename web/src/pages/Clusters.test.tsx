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
    namespaceId: "ns-acme",
    namespaceName: "acme",
    description: "production",
    autoIngest: true,
    lastSeenAt: new Date().toISOString(),
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
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
        const { container } = renderPage([{ ...prod, lastSeenAt: "" }]);
        expect(container.textContent).toContain("never reported");
    });

    it("flags a cluster whose last snapshot is old as stale", () => {
        const { container } = renderPage([
            { ...prod, lastSeenAt: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString() },
        ]);
        expect(container.textContent).toContain("stale");
    });

    // ocidex-70eo.4: the server's verdict wins, and its reason is the title.
    it("shows an erroring agent with the server's reason", () => {
        const { container } = renderPage([
            { ...prod, health: { state: "erroring", reason: "The agent's API key was not accepted" } },
        ]);
        const pill = [...container.querySelectorAll(".badge")].find((b) => b.textContent.startsWith("erroring"));
        expect(pill?.getAttribute("title")).toBe("The agent's API key was not accepted");
    });

    it("trusts the server's stale verdict over the client's hour", () => {
        const { container } = renderPage([{ ...prod, health: { state: "stale", reason: "No snapshot for 16m" } }]);
        expect(container.textContent).toContain("stale");
    });

    it("does not call a fresh cluster stale", () => {
        const { container } = renderPage();
        expect(container.textContent).not.toContain("stale");
        expect(container.textContent).not.toContain("never reported");
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
            // Carried through unchanged: a rename that omitted this would be
            // read by the API as "leave it alone", but sending the value the
            // row was showing keeps the form honest either way.
            autoIngest: true,
        });
    });

    // Ingest spends the namespace's registry credentials, so the state is
    // visible on every row rather than buried behind Edit.
    it("shows each cluster's auto-ingest state without entering edit mode", () => {
        const { container } = renderPage([prod, { ...prod, id: "c-dev", autoIngest: false }]);

        const rows = [...container.querySelectorAll("tbody tr")];
        expect(must(rows[0], "first row").textContent).toContain("On");
        expect(must(rows[1], "second row").textContent).toContain("Off");
    });

    it("turns auto-ingest off through the same save as a rename", () => {
        const { container } = renderPage();

        fireEvent.click(button(container, "Edit"));
        const toggle = must(
            container.querySelector('[data-testid="edit-auto-ingest"]'),
            "auto-ingest toggle",
        );
        fireEvent.click(toggle);
        fireEvent.click(button(container, "Save"));

        expect(updateMutate.mock.calls[0][0]).toEqual({
            id: "c-prod",
            name: "prod-eu-west",
            description: "production",
            autoIngest: false,
        });
    });

    // ocidex-70eo.9: retiring opens a dialog offering pause or delete, and
    // says what deletion takes with it, rather than a bare confirm().
    it("retires through a dialog that explains pause and delete", () => {
        const dialogProto = globalThis.HTMLDialogElement.prototype as { showModal: () => void };
        const original = dialogProto.showModal;
        dialogProto.showModal = vi.fn();
        try {
            const { container } = renderPage();
            fireEvent.click(button(container, "Retire"));
            expect(deleteMutate).not.toHaveBeenCalled();

            const dialog = must(container.querySelector('[data-testid="retire-dialog"]'), "retire dialog");
            expect(dialog.textContent).toContain("helm uninstall ocidex-k8s-agent");
            expect(dialog.textContent).toContain("agent credentials are revoked");
            expect(dialog.textContent).toContain("protection from retention");

            fireEvent.click(button(container, "Pause cluster"));
            expect(updateMutate.mock.calls[0][0]).toMatchObject({ id: "c-prod", paused: true });

            fireEvent.click(button(container, "Delete prod-eu-west"));
            expect(deleteMutate).toHaveBeenCalledWith("c-prod", expect.anything());
        } finally {
            dialogProto.showModal = original;
        }
    });

    it("offers resume on a paused cluster", () => {
        const { container } = renderPage([
            { ...prod, pausedAt: "2026-11-14T00:00:00Z", health: { state: "paused", reason: "Paused" } },
        ]);
        expect(container.textContent).toContain("paused");
        fireEvent.click(button(container, "Resume"));
        expect(updateMutate.mock.calls[0][0]).toMatchObject({ id: "c-prod", paused: false });
    });


    // ocidex-70eo.6: connecting is its own page; the list only links to it.
    it("links to the connect page instead of a register form", () => {
        const { container } = renderPage();
        const link = [...container.querySelectorAll("a")].find((a) => a.textContent.trim() === "Connect a cluster");
        expect(must(link, "connect link").getAttribute("href")).toBe("/clusters/new");
        expect(container.querySelector("form")).toBeNull();
    });
});
