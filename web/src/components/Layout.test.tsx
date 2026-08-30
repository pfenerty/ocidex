// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import Layout from "~/components/Layout";
import type { JSX } from "solid-js";

vi.mock("~/components/ThemeToggle", () => ({ default: () => null }));

vi.mock("~/api/client", () => ({
    API_BASE_URL: "",
    client: {},
    APIClientError: class extends Error {},
    unwrap: vi.fn(),
}));

const mockNavigate = vi.fn();
const mockLocation = { pathname: "/artifacts" };

vi.mock("@solidjs/router", () => ({
    // `aria-label` is forwarded on purpose: it is what names a nav link in the
    // mobile rail, where the <span> label is hidden and so is out of the
    // accessibility tree.
    A: (props: {
        href: string;
        children?: JSX.Element;
        class?: string;
        end?: boolean;
        "aria-label"?: string;
        // Forwarded for the same reason aria-label is: it is the whole
        // observable form of the role emphasis on the rail, and a mock that
        // dropped it would make those assertions vacuous.
        "data-lead"?: string;
    }) => (
        <a
            href={props.href}
            class={props.class}
            aria-label={props["aria-label"]}
            data-lead={props["data-lead"]}
        >
            {props.children}
        </a>
    ),
    useNavigate: () => mockNavigate,
    useLocation: () => mockLocation,
}));

const mockRefetch = vi.fn();
let mockUserFn: (() => User | undefined) & { loading: boolean };

vi.mock("~/context/auth", () => ({
    useAuth: () => ({ user: mockUserFn, refetch: mockRefetch }),
}));

interface Membership { namespace_id: string; role: string }
interface User { id: string; display_name: string; role: string; memberships?: Membership[] }

function makeUser(overrides?: Partial<User>): User {
    return { id: "1", display_name: "alice", role: "user", ...overrides };
}

/** Memberships in the shape /users/me reports them, from role names. */
function member(...roles: string[]): Membership[] {
    return roles.map((role, i) => ({ namespace_id: `n${String(i)}`, role }));
}

// Layout mounts the command palette, which holds four search queries. They are
// disabled with an empty term and never fetch, but createQuery still needs a
// client — App.tsx puts the provider above Layout, so the test does too.
function Wrapped(props: { children: JSX.Element }) {
    return (
        <QueryClientProvider client={new QueryClient()}>
            <Layout>{props.children}</Layout>
        </QueryClientProvider>
    );
}

function asResource(user?: User, loading = false) {
    return Object.assign(() => user, { loading });
}

describe("Layout", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockLocation.pathname = "/artifacts";
    });

    it("renders sidebar with brand on non-login path", () => {
        mockUserFn = asResource(makeUser());
        const { getByText } = render(() => <Wrapped>page</Wrapped>);
        // "SBOM Explorer" is the sidebar tagline, unbroken in a single element
        expect(getByText("SBOM Explorer")).toBeDefined();
        expect(getByText("page")).toBeDefined();
    });

    it("passes children through without sidebar on /login path", () => {
        mockLocation.pathname = "/login";
        mockUserFn = asResource(undefined);
        const { getByText, queryByText } = render(() => <Wrapped>login-content</Wrapped>);
        expect(getByText("login-content")).toBeDefined();
        expect(queryByText("OCIDex")).toBeNull();
    });

    it("shows Admin nav link for admin user", () => {
        mockUserFn = asResource(makeUser({ role: "admin" }));
        const { getByText } = render(() => <Wrapped>page</Wrapped>);
        expect(getByText("Admin")).toBeDefined();
    });

    it("hides Admin nav link for non-admin user", () => {
        mockUserFn = asResource(makeUser({ role: "user" }));
        const { queryByText } = render(() => <Wrapped>page</Wrapped>);
        expect(queryByText("Admin")).toBeNull();
    });

    it("shows display_name when authenticated", () => {
        mockUserFn = asResource(makeUser({ display_name: "alice" }));
        const { getByText } = render(() => <Wrapped>page</Wrapped>);
        expect(getByText("alice")).toBeDefined();
    });

    it("shows sign-in link when not authenticated", () => {
        mockUserFn = asResource(undefined);
        const { getByText } = render(() => <Wrapped>page</Wrapped>);
        expect(getByText("Sign in with GitHub")).toBeDefined();
    });

    it("redirects to /login when unauthenticated on /admin path", () => {
        mockLocation.pathname = "/admin";
        mockUserFn = asResource(undefined);
        render(() => <Wrapped>page</Wrapped>);
        expect(mockNavigate).toHaveBeenCalledWith("/login", { replace: true });
    });

    it("does not redirect authenticated user on /admin path", () => {
        mockLocation.pathname = "/admin";
        mockUserFn = asResource(makeUser({ role: "admin" }));
        render(() => <Wrapped>page</Wrapped>);
        expect(mockNavigate).not.toHaveBeenCalled();
    });

    // Every public route must survive a signed-out visit. `authedPaths` is a
    // prefix match, so adding a bare "/" — or a prefix that happens to cover a
    // public detail route — would bounce anonymous readers off pages the API
    // serves them anonymously (/api/v1/stats, /discover and /vulns/{id} all
    // answer 200 with no session).
    it.each(["/", "/vulnerabilities/CVE-2026-46595", "/artifacts", "/components"])(
        "does not redirect an unauthenticated visitor on %s",
        (path) => {
            mockLocation.pathname = path;
            mockUserFn = asResource(undefined);
            render(() => <Wrapped>page</Wrapped>);
            expect(mockNavigate).not.toHaveBeenCalled();
        },
    );

    it("calls fetch and refetch when logout button is clicked", async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true });
        vi.stubGlobal("fetch", mockFetch);

        mockUserFn = asResource(makeUser());
        const { getByTitle } = render(() => <Wrapped>page</Wrapped>);

        fireEvent.click(getByTitle("Sign out"));
        await Promise.resolve();

        expect(mockFetch).toHaveBeenCalledWith(
            "/auth/logout",
            expect.objectContaining({ method: "POST" })
        );
        expect(mockRefetch).toHaveBeenCalled();

        vi.unstubAllGlobals();
    });
});

/**
 * Below 768px the sidebar collapses to a 56px icon rail and this button opens
 * it back up. The CSS half of the contract — which labels the rail hides and
 * the drawer restores — is asserted in `sidebarRailContract.test.ts`, since
 * happy-dom has no layout engine and no media queries to evaluate.
 */
describe("Layout mobile drawer", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockLocation.pathname = "/artifacts";
        mockUserFn = asResource(makeUser());
    });

    it("starts closed", () => {
        const { getByLabelText, container } = render(() => <Wrapped>page</Wrapped>);
        const toggle = getByLabelText("Open navigation");
        expect(toggle.getAttribute("aria-expanded")).toBe("false");
        expect(container.querySelector(".sidebar-open")).toBeNull();
        expect(container.querySelector(".sidebar-backdrop")).toBeNull();
    });

    it("opens the drawer and its backdrop when the toggle is clicked", () => {
        const { getByLabelText, container } = render(() => <Wrapped>page</Wrapped>);
        fireEvent.click(getByLabelText("Open navigation"));

        expect(container.querySelector(".sidebar-open")).not.toBeNull();
        expect(container.querySelector(".sidebar-backdrop")).not.toBeNull();
        expect(getByLabelText("Close navigation").getAttribute("aria-expanded")).toBe("true");
    });

    it("closes when the backdrop is tapped", () => {
        const { getByLabelText, container } = render(() => <Wrapped>page</Wrapped>);
        fireEvent.click(getByLabelText("Open navigation"));

        const backdrop = container.querySelector(".sidebar-backdrop");
        if (backdrop === null) throw new Error("the drawer rendered no backdrop");
        fireEvent.click(backdrop);

        expect(container.querySelector(".sidebar-open")).toBeNull();
    });

    it("closes on Escape", () => {
        const { getByLabelText, container } = render(() => <Wrapped>page</Wrapped>);
        fireEvent.click(getByLabelText("Open navigation"));
        expect(container.querySelector(".sidebar-open")).not.toBeNull();

        fireEvent.keyDown(window, { key: "Escape" });
        expect(container.querySelector(".sidebar-open")).toBeNull();
    });

    // The rail hides these labels with `display: none`, which takes them out of
    // the accessibility tree too — so an icon-only link needs its own name.
    it("names every nav link even with its label hidden", () => {
        mockUserFn = asResource(makeUser({ role: "admin" }));
        const { container } = render(() => <Wrapped>page</Wrapped>);
        // Scoped to the sidebar: the command palette is mounted alongside it
        // and offers the same route names.
        const sidebar = container.querySelector("aside.sidebar");
        if (sidebar === null) throw new Error("no sidebar rendered");
        for (const name of ["Home", "Workspace", "Artifacts", "Components", "Licenses",
            "Vulnerabilities", "Compare", "Clusters", "Admin", "Search", "Sign out"]) {
            expect(sidebar.querySelector(`[aria-label="${name}"]`)).not.toBeNull();
        }
    });

    describe("role emphasis", () => {
        const railHrefs = (container: HTMLElement) =>
            [...(container.querySelector("aside.sidebar nav")?.querySelectorAll("a") ?? [])].map(
                (a) => a.getAttribute("href"),
            );
        const led = (container: HTMLElement) =>
            [...(container.querySelector("aside.sidebar nav")?.querySelectorAll("a[data-lead]") ?? [])].map(
                (a) => a.getAttribute("href"),
            );

        it("accents the security links for a mostly-security caller", () => {
            mockUserFn = asResource(makeUser({ memberships: member("security", "security", "developer") }));
            const { container } = render(() => <Wrapped>page</Wrapped>);
            expect(led(container)).toEqual(["/vulnerabilities", "/clusters"]);
        });

        it("accents the shipping links for a mostly-developer caller", () => {
            mockUserFn = asResource(makeUser({ memberships: member("developer") }));
            const { container } = render(() => <Wrapped>page</Wrapped>);
            expect(led(container)).toEqual(["/artifacts", "/admin/sources"]);
        });

        it("accents nothing for an owner", () => {
            mockUserFn = asResource(makeUser({ memberships: member("owner", "security") }));
            const { container } = render(() => <Wrapped>page</Wrapped>);
            expect(led(container)).toEqual([]);
        });

        // The rail is accented, never reordered and never filtered: the same
        // links in the same order for every emphasis. Link position is muscle
        // memory, and a link that vanishes per persona hides a page the caller
        // is still allowed to open.
        it("shows the same links in the same order under every emphasis", () => {
            let expected: (string | null)[] | undefined;
            for (const roles of [["security"], ["developer"], ["owner"], []]) {
                mockUserFn = asResource(makeUser({ memberships: member(...roles) }));
                const { container, unmount } = render(() => <Wrapped>page</Wrapped>);
                const hrefs = railHrefs(container);
                expected ??= hrefs;
                expect(hrefs).toEqual(expected);
                unmount();
            }
        });
    });
});
