// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
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
    A: (props: { href: string; children?: JSX.Element; class?: string; end?: boolean }) => (
        <a href={props.href} class={props.class}>{props.children}</a>
    ),
    useNavigate: () => mockNavigate,
    useLocation: () => mockLocation,
}));

const mockRefetch = vi.fn();
let mockUserFn: (() => User | undefined) & { loading: boolean };

vi.mock("~/context/auth", () => ({
    useAuth: () => ({ user: mockUserFn, refetch: mockRefetch }),
}));

interface User { id: string; github_username: string; role: string }

function makeUser(overrides?: Partial<User>): User {
    return { id: "1", github_username: "alice", role: "user", ...overrides };
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
        const { getByText } = render(() => <Layout>page</Layout>);
        // "SBOM Explorer" is the sidebar tagline, unbroken in a single element
        expect(getByText("SBOM Explorer")).toBeDefined();
        expect(getByText("page")).toBeDefined();
    });

    it("passes children through without sidebar on /login path", () => {
        mockLocation.pathname = "/login";
        mockUserFn = asResource(undefined);
        const { getByText, queryByText } = render(() => <Layout>login-content</Layout>);
        expect(getByText("login-content")).toBeDefined();
        expect(queryByText("OCIDex")).toBeNull();
    });

    it("shows Admin nav link for admin user", () => {
        mockUserFn = asResource(makeUser({ role: "admin" }));
        const { getByText } = render(() => <Layout>page</Layout>);
        expect(getByText("Admin")).toBeDefined();
    });

    it("hides Admin nav link for non-admin user", () => {
        mockUserFn = asResource(makeUser({ role: "user" }));
        const { queryByText } = render(() => <Layout>page</Layout>);
        expect(queryByText("Admin")).toBeNull();
    });

    it("shows github_username when authenticated", () => {
        mockUserFn = asResource(makeUser({ github_username: "alice" }));
        const { getByText } = render(() => <Layout>page</Layout>);
        expect(getByText("alice")).toBeDefined();
    });

    it("shows sign-in link when not authenticated", () => {
        mockUserFn = asResource(undefined);
        const { getByText } = render(() => <Layout>page</Layout>);
        expect(getByText("Sign in with GitHub")).toBeDefined();
    });

    it("redirects to /login when unauthenticated on /admin path", () => {
        mockLocation.pathname = "/admin";
        mockUserFn = asResource(undefined);
        render(() => <Layout>page</Layout>);
        expect(mockNavigate).toHaveBeenCalledWith("/login", { replace: true });
    });

    it("does not redirect authenticated user on /admin path", () => {
        mockLocation.pathname = "/admin";
        mockUserFn = asResource(makeUser({ role: "admin" }));
        render(() => <Layout>page</Layout>);
        expect(mockNavigate).not.toHaveBeenCalled();
    });

    it("calls fetch and refetch when logout button is clicked", async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true });
        vi.stubGlobal("fetch", mockFetch);

        mockUserFn = asResource(makeUser());
        const { getByTitle } = render(() => <Layout>page</Layout>);

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
