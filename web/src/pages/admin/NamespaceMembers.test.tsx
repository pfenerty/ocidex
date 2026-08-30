// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import {
    useListUsers,
    useNamespaceMembers,
    useSetNamespaceMember,
    useRemoveNamespaceMember,
} from "~/api/queries";
import { useAuth } from "~/context/auth";
import { NamespaceMembers } from "~/pages/admin/NamespaceMembers";

const setMutate = vi.fn();
const removeMutate = vi.fn();

vi.mock("~/api/queries", () => ({
    useListUsers: vi.fn(),
    useNamespaceMembers: vi.fn(),
    useSetNamespaceMember: vi.fn(),
    useRemoveNamespaceMember: vi.fn(),
}));

vi.mock("~/context/auth", () => ({ useAuth: vi.fn() }));
vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

const mockUsers = vi.mocked(useListUsers);
const mockMembers = vi.mocked(useNamespaceMembers);
const mockSet = vi.mocked(useSetNamespaceMember);
const mockRemove = vi.mocked(useRemoveNamespaceMember);
const mockAuth = vi.mocked(useAuth);

const acme = {
    id: "ns-acme",
    name: "acme",
    visibility: "private" as const,
    owner_id: "u-owner",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
};

const owner = {
    user_id: "u-owner",
    username: "octocat",
    role: "owner" as const,
    capabilities: ["manage_member"],
    created_at: "2026-01-01T00:00:00Z",
};

const viewer = {
    user_id: "u-viewer",
    username: "hubot",
    role: "viewer" as const,
    capabilities: ["read_private"],
    created_at: "2026-01-02T00:00:00Z",
};

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

function select(container: HTMLElement, label: string): HTMLSelectElement {
    return must(container.querySelector<HTMLSelectElement>(`select[aria-label="${label}"]`), label);
}

/**
 * caller is the signed-in user. `role` is the *installation* role; namespace
 * ownership is expressed by matching `acme.owner_id`, which is what the panel
 * actually keys its visibility on.
 */
function renderPanel(
    caller: { id: string; role: string } | undefined,
    members = [owner, viewer],
    users: unknown[] = [{ id: "u-new", github_username: "monalisa" }],
) {
    mockAuth.mockReturnValue({ user: () => caller, refetch: vi.fn() } as never);
    mockMembers.mockImplementation((() => ({
        data: { data: members },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockUsers.mockImplementation((() => ({
        data: { users },
        isLoading: false,
        isError: false,
        error: null,
    })) as never);
    mockSet.mockImplementation((() => ({ mutate: setMutate, isPending: false })) as never);
    mockRemove.mockImplementation((() => ({ mutate: removeMutate, isPending: false })) as never);
    return render(() => <NamespaceMembers namespace={acme} onClose={vi.fn()} />);
}

describe("NamespaceMembers", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("renders nothing at all for a caller without manage_member", () => {
        const { container } = renderPanel({ id: "u-viewer", role: "member" });
        expect(container.querySelector('[data-testid="namespace-members"]')).toBeNull();
    });

    it("renders for the namespace owner and for an installation admin", () => {
        const asOwner = renderPanel({ id: "u-owner", role: "member" });
        expect(asOwner.container.querySelector('[data-testid="namespace-members"]')).not.toBeNull();

        const asAdmin = renderPanel({ id: "u-someone-else", role: "admin" });
        expect(asAdmin.container.querySelector('[data-testid="namespace-members"]')).not.toBeNull();
    });

    it("lists each member with their role and capabilities", () => {
        const { container } = renderPanel({ id: "u-owner", role: "member" });
        const rows = [...container.querySelectorAll("tbody tr")];
        expect(rows.length).toBe(2);
        const cells = [...rows[1].querySelectorAll("td")].map((c) => c.textContent.trim());
        expect(cells[0]).toBe("hubot");
        expect(cells[2]).toBe("read_private");
    });

    it("offers no role selector and no remove button on the owner row", () => {
        const { container } = renderPanel({ id: "u-owner", role: "member" });
        const ownerRow = must(container.querySelector("tbody tr"), "owner row");
        expect(ownerRow.querySelector("select")).toBeNull();
        expect(ownerRow.querySelector("button")).toBeNull();
    });

    it("changes a member's role", () => {
        const { container } = renderPanel({ id: "u-owner", role: "member" });
        fireEvent.change(select(container, "Role for hubot"), { target: { value: "developer" } });

        expect(setMutate).toHaveBeenCalledTimes(1);
        expect(setMutate.mock.calls[0][0]).toEqual({
            id: "ns-acme",
            userID: "u-viewer",
            role: "developer",
        });
    });

    it("adds a member, offering only users who are not members yet", () => {
        const { container } = renderPanel({ id: "u-owner", role: "member" }, [owner, viewer], [
            { id: "u-new", github_username: "monalisa" },
            { id: "u-viewer", github_username: "hubot" },
        ]);

        const picker = select(container, "User to add");
        const offered = [...picker.querySelectorAll("option")].map((o) => o.value);
        expect(offered).toEqual(["", "u-new"]);

        fireEvent.change(picker, { target: { value: "u-new" } });
        fireEvent.change(select(container, "Role to grant"), { target: { value: "maintainer" } });
        fireEvent.submit(must(container.querySelector("form"), "add form"));

        expect(setMutate.mock.calls[0][0]).toEqual({
            id: "ns-acme",
            userID: "u-new",
            role: "maintainer",
        });
    });

    it("removes a member only on confirm", () => {
        const confirmSpy = vi.fn((_message?: string) => false);
        vi.stubGlobal("confirm", confirmSpy);
        const { container } = renderPanel({ id: "u-owner", role: "member" });

        fireEvent.click(button(container, "Remove"));
        expect(removeMutate).not.toHaveBeenCalled();
        expect(confirmSpy.mock.calls[0][0]).toContain("hubot");

        confirmSpy.mockReturnValue(true);
        fireEvent.click(button(container, "Remove"));
        expect(removeMutate.mock.calls[0][0]).toEqual({ id: "ns-acme", userID: "u-viewer" });
    });
});
