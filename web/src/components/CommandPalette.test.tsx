// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import CommandPalette, { openCommandPalette } from "./CommandPalette";

const mockNavigate = vi.fn();
vi.mock("@solidjs/router", () => ({ useNavigate: () => mockNavigate }));

/**
 * A stand-in corpus for the four catalog searches.
 *
 * The hooks are replaced rather than the fetch layer because what this file is
 * testing is the palette's behaviour around results — where they land, how the
 * highlight crosses them, what an errored group looks like — not how the four
 * endpoints are called. Each fake reads `term()` inside a getter, so it is as
 * reactive as the real query and narrows as the debounced term changes.
 *
 * `boom` is the error term: it stands in for a 401 reaching a signed-out
 * visitor, which since ocidex-ag4q.1 arrives as data rather than a redirect.
 */
vi.mock("~/api/queries", () => {
    const CORPUS: Record<string, { key: string; label: string; sub?: string; path: string }[]> = {
        artifacts: [
            { key: "a1", label: "ghcr.io/pfenerty/ocidex", sub: "container", path: "/artifacts/a1" },
        ],
        components: [
            { key: "c1", label: "openssl", sub: "12 versions", path: "/components/overview?name=openssl" },
        ],
        vulns: [
            { key: "v1", label: "CVE-2026-0001", sub: "CRITICAL", path: "/vulnerabilities/CVE-2026-0001" },
            { key: "v2", label: "CVE-2026-0002", sub: "HIGH", path: "/vulnerabilities/CVE-2026-0002" },
        ],
        licenses: [{ key: "l1", label: "OpenSSL License", sub: "OpenSSL", path: "/licenses/l1/components" }],
    };
    const make = (group: string) => (term: () => string) => ({
        get data() {
            const q = term().toLowerCase();
            if (q.length < 2 || q === "boom") return undefined;
            return CORPUS[group].filter((h) => h.label.toLowerCase().includes(q));
        },
        get isError() {
            return term() === "boom";
        },
        isFetching: false,
    });
    return {
        MIN_SEARCH_TERM: 2,
        useArtifactSearch: make("artifacts"),
        useComponentSearch: make("components"),
        useVulnerabilitySearch: make("vulns"),
        useLicenseSearch: make("licenses"),
    };
});

interface User { id: string; display_name: string; role: string }
let mockUserFn: (() => User | undefined) & { loading: boolean };
vi.mock("~/context/auth", () => ({ useAuth: () => ({ user: mockUserFn, refetch: vi.fn() }) }));

function asResource(user?: User, loading = false) {
    return Object.assign(() => user, { loading });
}
const admin = { id: "1", display_name: "alice", role: "admin" };
const member = { id: "2", display_name: "bob", role: "user" };

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

/**
 * Type, then let the 300ms debounce expire.
 *
 * Route entries filter on the keystroke itself; catalog results wait for this.
 * Tests that only care about the route list can use `fireEvent.input` directly
 * and never advance the clock — that is the pre-debounce state, and it is a real
 * one a user sees.
 */
function search(input: HTMLInputElement, text: string): void {
    fireEvent.input(input, { target: { value: text } });
    vi.advanceTimersByTime(400);
}

describe("CommandPalette", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
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
        expect(labels()).toEqual(["Vulnerabilities", 'Resolve artifact "cve"']);
    });

    it("does not claim nothing matched while a search is still out", () => {
        const { input, getByText } = mount(member);
        pressShortcut();
        // Typed, but the debounce has not fired: the catalog has not answered,
        // so "No matching page" would be a claim the palette cannot make yet.
        fireEvent.input(input(), { target: { value: "nothing-matches-this" } });
        expect(getByText("Searching…")).toBeTruthy();

        vi.advanceTimersByTime(400);
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
        expect(labels()).toEqual(["Compare", 'Resolve artifact "compare"']);
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
        expect(headings).toEqual(["Manage", "Look up"]);
    });

    it("puts catalog results beside the route entries, not instead of them", () => {
        const { input, dialog, labels } = mount(member);
        pressShortcut();
        search(input(), "openssl");

        const headings = Array.from(dialog.querySelectorAll(".command-palette-group")).map(
            (h) => h.textContent,
        );
        // The route list keeps no match for "openssl", so only catalog groups
        // remain — and both of the ones that matched are present.
        expect(headings).toEqual(["Components", "Licenses", "Look up"]);
        expect(labels()).toEqual(["openssl", "OpenSSL License", 'Resolve artifact "openssl"']);
    });

    it("keeps offering the page when a term matches both a route and the catalog", () => {
        const { input, dialog } = mount(member);
        pressShortcut();
        search(input(), "cve");

        const headings = Array.from(dialog.querySelectorAll(".command-palette-group")).map(
            (h) => h.textContent,
        );
        expect(headings).toEqual(["Explore", "Vulnerabilities", "Look up"]);
    });

    it("navigates to a catalog hit, not only to a route", () => {
        const { input, options } = mount(member);
        pressShortcut();
        search(input(), "cve");
        // Explore/Vulnerabilities is first; the two CVEs follow it.
        fireEvent.mouseDown(options()[1]);
        expect(mockNavigate).toHaveBeenCalledWith("/vulnerabilities/CVE-2026-0001");
    });

    it("walks route entries and catalog hits with one continuous highlight", () => {
        const { input } = mount(member);
        pressShortcut();
        search(input(), "cve");
        // Down twice from the Vulnerabilities page lands on the second CVE:
        // the arrow keys do not stop at the boundary between the two kinds.
        fireEvent.keyDown(input(), { key: "ArrowDown" });
        fireEvent.keyDown(input(), { key: "ArrowDown" });
        fireEvent.keyDown(input(), { key: "Enter" });
        expect(mockNavigate).toHaveBeenCalledWith("/vulnerabilities/CVE-2026-0002");
    });

    it("renders a group that errored as absent, not as a failure", () => {
        const { input, dialog, getByText } = mount(undefined);
        pressShortcut();
        // "boom" stands in for a 401 from one of the four endpoints.
        search(input(), "boom");

        // Only the resolver row is left standing — and it is not a match, so
        // the palette still says nothing matched.
        expect(
            Array.from(dialog.querySelectorAll(".command-palette-group")).map((h) => h.textContent),
        ).toEqual(["Look up"]);
        expect(getByText("No matching page")).toBeTruthy();
        // The point of the story: a 401 is data. It must not have navigated.
        expect(mockNavigate).not.toHaveBeenCalled();
    });

    it("offers the ADR-042 artifact resolver, with the name in a query param", () => {
        const { input, options, labels } = mount(member);
        pressShortcut();
        // A name with slashes in it — which is why ADR-042 keys the resolver on
        // a query param rather than a path segment.
        search(input(), "ghcr.io/pfenerty/ocidex");
        const all = labels();
        expect(all[all.length - 1]).toBe('Resolve artifact "ghcr.io/pfenerty/ocidex"');

        fireEvent.mouseDown(options()[options().length - 1]);
        expect(mockNavigate).toHaveBeenCalledWith(
            "/artifacts/lookup?name=ghcr.io%2Fpfenerty%2Focidex",
        );
    });

    it("sends a digest to the SBOM resolver, prefix or not", () => {
        const hex = "a".repeat(64);
        const { input, options } = mount(member);
        pressShortcut();
        search(input(), hex);
        fireEvent.mouseDown(options()[options().length - 1]);
        expect(mockNavigate).toHaveBeenCalledWith(
            `/sboms/lookup?digest=sha256%3A${hex}`,
        );
    });

    it("sends a purl to the occurrence list, which ADR-042 excludes from lookup", () => {
        const { input, options, labels } = mount(member);
        pressShortcut();
        search(input(), "pkg:golang/openssl@1.1");
        const all = labels();
        expect(all[all.length - 1]).toBe("Every SBOM carrying pkg:golang/openssl@1.1");

        fireEvent.mouseDown(options()[options().length - 1]);
        expect(mockNavigate).toHaveBeenCalledWith(
            "/components?purl=pkg%3Agolang%2Fopenssl%401.1",
        );
    });

    it("keeps a picked catalog hit on its own id, not back through a resolver", () => {
        const { input, options } = mount(member);
        pressShortcut();
        search(input(), "openssl");
        // The first row is the component hit. It has already been
        // disambiguated, so routing it by name would only earn a 409.
        fireEvent.mouseDown(options()[0]);
        expect(mockNavigate).toHaveBeenCalledWith("/components/overview?name=openssl");
    });

    it("offers no resolver row until the term is worth resolving", () => {
        const { input, labels } = mount(member);
        pressShortcut();
        fireEvent.input(input(), { target: { value: "a" } });
        expect(labels().some((l) => (l ?? "").startsWith("Resolve"))).toBe(false);
    });

    it("does not search on a single character", () => {
        const { input, labels } = mount(member);
        pressShortcut();
        search(input(), "o");
        // Route entries still filter — "o" is in most of them — but nothing
        // from the catalog joins them.
        expect(labels()).not.toContain("openssl");
        expect(labels()).not.toContain("OpenSSL License");
    });

    it("drops catalog hits when the term is cleared, despite the kept cache", () => {
        const { input, labels } = mount(member);
        pressShortcut();
        search(input(), "openssl");
        expect(labels()).toContain("openssl");

        search(input(), "");
        expect(labels()).not.toContain("openssl");
        expect(labels()).toContain("Home");
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
