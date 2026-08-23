// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import CommandPalette, { openCommandPalette } from "./CommandPalette";

const mockNavigate = vi.fn();
vi.mock("@solidjs/router", () => ({ useNavigate: () => mockNavigate }));

interface User { id: string; github_username: string; role: string }
let mockUserFn: (() => User | undefined) & { loading: boolean };
vi.mock("~/context/auth", () => ({ useAuth: () => ({ user: mockUserFn, refetch: vi.fn() }) }));

function asResource(user?: User, loading = false) {
    return Object.assign(() => user, { loading });
}
const admin = { id: "1", github_username: "alice", role: "admin" };
const member = { id: "2", github_username: "bob", role: "user" };

function mount(user?: User) {
    mockUserFn = asResource(user);
    const r = render(() => <CommandPalette />);
    const dialog = r.container.querySelector("dialog");
    if (dialog === null) throw new Error("no dialog rendered");
    // Fails loudly if a previous test leaked the module-level open signal.
    expect(dialog.open).toBe(false);
    const input = (): HTMLInputElement => {
        const el = dialog.querySelector<HTMLInputElement>("input[role='combobox']");
        if (el === null) throw new Error("no input rendered");
        return el;
    };
    const options = (): Element[] => Array.from(dialog.querySelectorAll("[role='option']"));
    const labels = (): (string | null)[] =>
        options().map((o) => o.querySelector(".command-palette-label")?.textContent ?? null);
    return { ...r, dialog, input, options, labels };
}

/** The shortcut, as the browser delivers it — from the document, not the input. */
function pressShortcut(): void {
    fireEvent.keyDown(document, { key: "k", metaKey: true });
}

describe("CommandPalette", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("stays shut until the shortcut, and shuts again on Escape", () => {
        const { dialog } = mount(member);
        expect(dialog.open).toBe(false);

        pressShortcut();
        expect(dialog.open).toBe(true);

        fireEvent.keyDown(document, { key: "Escape" });
        expect(dialog.open).toBe(false);
    });

    it("toggles on a second shortcut rather than reopening", () => {
        const { dialog } = mount(member);
        pressShortcut();
        pressShortcut();
        expect(dialog.open).toBe(false);
    });

    it("opens from the sidebar trigger, not only from the keyboard", () => {
        // The sidebar button calls this directly; without it the feature is
        // reachable only by someone who already knows it exists.
        const { dialog, input } = mount(member);
        openCommandPalette();
        expect(dialog.open).toBe(true);
        expect(document.activeElement).toBe(input());
        fireEvent.keyDown(document, { key: "Escape" });
    });

    it("filters on keywords the label never shows", () => {
        const { input, labels } = mount(member);
        pressShortcut();
        // "cve" appears nowhere in "Vulnerabilities" — only in its keywords.
        fireEvent.input(input(), { target: { value: "cve" } });
        expect(labels()).toEqual(["Vulnerabilities"]);
    });

    it("says so when nothing matches, instead of showing an empty box", () => {
        const { input, options, getByText } = mount(member);
        pressShortcut();
        fireEvent.input(input(), { target: { value: "nothing-matches-this" } });
        expect(options()).toHaveLength(0);
        expect(getByText("No matching page")).toBeTruthy();
    });

    it("walks the list with the arrows and navigates on Enter", () => {
        const { input, dialog } = mount(member);
        pressShortcut();
        fireEvent.keyDown(input(), { key: "ArrowDown" }); // Home -> Artifacts
        fireEvent.keyDown(input(), { key: "Enter" });

        expect(mockNavigate).toHaveBeenCalledWith("/artifacts");
        expect(dialog.open).toBe(false);
    });

    it("wraps the highlight rather than sticking at the top", () => {
        const { input, labels } = mount(member);
        pressShortcut();
        const all = labels();
        const last = all[all.length - 1];
        fireEvent.keyDown(input(), { key: "ArrowUp" });
        fireEvent.keyDown(input(), { key: "Enter" });
        expect(last).toBe("Sources");
        expect(mockNavigate).toHaveBeenCalledWith("/admin/sources");
    });

    it("selects on mousedown, before the input can lose focus", () => {
        const { input, options, labels } = mount(member);
        pressShortcut();
        fireEvent.input(input(), { target: { value: "compare" } });
        expect(labels()).toEqual(["Compare"]);
        fireEvent.mouseDown(options()[0]);
        expect(mockNavigate).toHaveBeenCalledWith("/diff");
    });

    it("offers a signed-out visitor only what they can reach", () => {
        const { labels } = mount(undefined);
        pressShortcut();
        const seen = labels();
        // Offering these would navigate straight into a redirect back to /login.
        expect(seen).not.toContain("Workspace");
        expect(seen).not.toContain("Clusters");
        expect(seen).not.toContain("Sources");
        expect(seen).toContain("Sign in");
        expect(seen).toContain("Vulnerabilities");
    });

    it("hides the admin-only entries from an ordinary member, and Sign in from both", () => {
        const asMember = mount(member);
        pressShortcut();
        expect(asMember.labels()).toContain("Sources");
        expect(asMember.labels()).not.toContain("API keys");
        expect(asMember.labels()).not.toContain("Sign in");
        asMember.unmount();

        const asAdmin = mount(admin);
        pressShortcut();
        expect(asAdmin.labels()).toContain("API keys");
        expect(asAdmin.labels()).toContain("Jobs");
    });

    it("groups results under headings without breaking the flat highlight", () => {
        const { dialog, input } = mount(admin);
        pressShortcut();
        const headings = Array.from(dialog.querySelectorAll(".command-palette-group")).map(
            (h) => h.textContent,
        );
        expect(headings).toEqual(["Explore", "Workspace", "Manage"]);

        // Six steps down from Home lands on Compare, the seventh entry overall
        // and the last one under Explore: the highlight counts entries, not
        // groups, and does not stall at a heading.
        for (let i = 0; i < 6; i++) fireEvent.keyDown(input(), { key: "ArrowDown" });
        fireEvent.keyDown(input(), { key: "Enter" });
        expect(mockNavigate).toHaveBeenCalledWith("/diff");
    });

    it("drops a heading whose group has no matches left", () => {
        const { dialog, input } = mount(admin);
        pressShortcut();
        fireEvent.input(input(), { target: { value: "queue" } });
        const headings = Array.from(dialog.querySelectorAll(".command-palette-group")).map(
            (h) => h.textContent,
        );
        expect(headings).toEqual(["Manage"]);
    });

    it("clears the query when it closes, so it opens fresh", () => {
        const { input } = mount(member);
        pressShortcut();
        fireEvent.input(input(), { target: { value: "licenses" } });
        fireEvent.keyDown(document, { key: "Escape" });
        pressShortcut();
        expect(input().value).toBe("");
    });
});
