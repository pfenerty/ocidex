// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import {
    useListNamespaces,
    useListSources,
    useCreateNamespace,
    useUpdateNamespace,
    useDeleteNamespace,
} from "~/api/queries";
import { NamespacesTab } from "~/pages/admin/NamespacesTab";

const createMutate = vi.fn();
const updateMutate = vi.fn();
const deleteMutate = vi.fn();

vi.mock("~/api/queries", () => ({
    useListNamespaces: vi.fn(),
    useListSources: vi.fn(),
    useCreateNamespace: vi.fn(),
    useUpdateNamespace: vi.fn(),
    useDeleteNamespace: vi.fn(),
}));

vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

const mockList = vi.mocked(useListNamespaces);
const mockSources = vi.mocked(useListSources);
const mockCreate = vi.mocked(useCreateNamespace);
const mockUpdate = vi.mocked(useUpdateNamespace);
const mockDelete = vi.mocked(useDeleteNamespace);

const acme = {
    id: "ns-acme",
    name: "acme",
    visibility: "private" as const,
    owner_username: "octocat",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
};

function mutation(mutate: ReturnType<typeof vi.fn>) {
    return (() => ({ mutate, isPending: false })) as never;
}

function renderTab(namespaces = [acme], sources: unknown[] = []) {
    mockList.mockImplementation((() => ({
        data: { data: namespaces },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockSources.mockImplementation((() => ({
        data: { data: sources },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockCreate.mockImplementation(mutation(createMutate));
    mockUpdate.mockImplementation(mutation(updateMutate));
    mockDelete.mockImplementation(mutation(deleteMutate));
    return render(() => <NamespacesTab />);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

/** The row action button with the given label. */
function button(container: HTMLElement, label: string): HTMLButtonElement {
    const found = [...container.querySelectorAll("button")].find(
        (b) => b.textContent.trim() === label,
    );
    return must(found, `${label} button`);
}

describe("NamespacesTab", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("lists each namespace with its visibility, owner and source count", () => {
        const { container } = renderTab(
            [acme],
            [{ id: "s1", namespace_id: "ns-acme" }, { id: "s2", namespace_id: "ns-acme" }],
        );

        const row = must(container.querySelector("tbody tr"), "namespace row");
        const cells = [...row.querySelectorAll("td")].map((c) => c.textContent.trim());
        expect(cells[0]).toBe("acme");
        expect(cells[1]).toBe("private");
        expect(cells[2]).toBe("octocat");
        expect(cells[3]).toBe("2");
    });

    it("creates a namespace with the chosen visibility", () => {
        const { container } = renderTab();

        const nameInput = must(container.querySelector("form input"), "name input");
        fireEvent.input(nameInput, { target: { value: "  widgets  " } });
        const select = must(container.querySelector("form select"), "visibility select");
        fireEvent.change(select, { target: { value: "public" } });
        fireEvent.submit(must(container.querySelector("form"), "create form"));

        expect(createMutate).toHaveBeenCalledTimes(1);
        expect(createMutate.mock.calls[0][0]).toEqual({ name: "widgets", visibility: "public" });
    });

    it("does not submit a blank name", () => {
        const { container } = renderTab();
        fireEvent.submit(must(container.querySelector("form"), "create form"));
        expect(createMutate).not.toHaveBeenCalled();
    });

    it("renames and re-scopes a namespace inline", () => {
        const { container } = renderTab();

        fireEvent.click(button(container, "Edit"));
        const nameInput = must(
            container.querySelector('[data-testid="edit-name"]'),
            "inline name input",
        );
        fireEvent.input(nameInput, { target: { value: "acme-corp" } });
        fireEvent.change(
            must(container.querySelector('[data-testid="edit-visibility"]'), "visibility select"),
            { target: { value: "public" } },
        );
        fireEvent.click(button(container, "Save"));

        expect(updateMutate).toHaveBeenCalledTimes(1);
        expect(updateMutate.mock.calls[0][0]).toEqual({
            id: "ns-acme",
            name: "acme-corp",
            visibility: "public",
        });
    });

    it("abandons an inline edit on cancel", () => {
        const { container } = renderTab();

        fireEvent.click(button(container, "Edit"));
        fireEvent.input(
            must(container.querySelector('[data-testid="edit-name"]'), "inline name input"),
            { target: { value: "nope" } },
        );
        fireEvent.click(button(container, "Cancel"));

        expect(updateMutate).not.toHaveBeenCalled();
        expect(container.querySelector('[data-testid="edit-name"]')).toBeNull();
    });

    it("names what a delete would take with it, and only deletes on confirm", () => {
        const confirmSpy = vi.fn((_message?: string) => false);
        vi.stubGlobal("confirm", confirmSpy);
        const { container } = renderTab([acme], [{ id: "s1", namespace_id: "ns-acme" }]);

        fireEvent.click(button(container, "Delete"));
        expect(deleteMutate).not.toHaveBeenCalled();
        expect(confirmSpy.mock.calls[0][0]).toContain("1 source and everything ingested under them");

        confirmSpy.mockReturnValue(true);
        fireEvent.click(button(container, "Delete"));
        expect(deleteMutate).toHaveBeenCalledWith("ns-acme", expect.anything());
    });
});
