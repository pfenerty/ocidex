// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { useMyNamespaces, useMyDriftFeed, useWatches } from "~/api/queries";
import { useAuth } from "~/context/auth";
import { HomeBand } from "./HomeBand";

vi.mock("~/api/queries", () => ({
    useMyNamespaces: vi.fn(),
    useMyDriftFeed: vi.fn(),
    useWatches: vi.fn(),
}));

vi.mock("~/context/auth", () => ({ useAuth: vi.fn() }));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; class?: string; children?: JSX.Element }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

const rows = (n: number) => ({ data: { data: Array.from({ length: n }, (_, i) => ({ i })) } });
const pending = { data: undefined };

function setUser(username: string | undefined) {
    vi.mocked(useAuth).mockReturnValue({
        user: (() =>
            username === undefined
                ? undefined
                : { id: "u1", github_username: username, role: "member" }) as unknown as ReturnType<
            typeof useAuth
        >["user"],
        refetch: vi.fn(),
    });
}

function setCounts(namespaces: number, watches: number, drift: number) {
    vi.mocked(useMyNamespaces).mockReturnValue(
        rows(namespaces) as unknown as ReturnType<typeof useMyNamespaces>,
    );
    vi.mocked(useWatches).mockReturnValue(rows(watches) as unknown as ReturnType<typeof useWatches>);
    vi.mocked(useMyDriftFeed).mockReturnValue(
        rows(drift) as unknown as ReturnType<typeof useMyDriftFeed>,
    );
}

beforeEach(() => {
    vi.clearAllMocks();
    setUser("octocat");
    setCounts(0, 0, 0);
});

describe("HomeBand", () => {
    // The <Show> in HomeBand gates markup, not the hooks — those run at
    // component scope. Before ocidex-ag4q.2 this passed while the component
    // still fired three /users/me/* requests that 401'd for every anonymous
    // visitor to the landing page.
    it("does not enable its self-scoped queries when signed out", () => {
        setUser(undefined);
        render(() => <HomeBand />);

        for (const hook of [useMyNamespaces, useWatches, useMyDriftFeed]) {
            expect(vi.mocked(hook).mock.calls[0]?.[0]?.enabled?.()).toBe(false);
        }
    });

    it("enables its self-scoped queries once a user is present", () => {
        setUser("octocat");
        render(() => <HomeBand />);

        for (const hook of [useMyNamespaces, useWatches, useMyDriftFeed]) {
            expect(vi.mocked(hook).mock.calls[0]?.[0]?.enabled?.()).toBe(true);
        }
    });

    it("renders nothing when signed out — the landing page stays public", () => {
        setUser(undefined);
        const { container } = render(() => <HomeBand />);
        expect(container.querySelector(".home-band")).toBeNull();
    });

    it("greets the signed-in user and offers a way into the workspace", () => {
        const { getByText } = render(() => <HomeBand />);
        expect(getByText("Welcome back, octocat")).toBeDefined();
        expect(getByText("Open workspace").closest("a")?.getAttribute("href")).toBe("/dashboard");
    });

    it("counts namespaces and watches, pluralising each", () => {
        setCounts(1, 3, 0);
        const { getByText } = render(() => <HomeBand />);
        expect(getByText("1 namespace")).toBeDefined();
        expect(getByText("3 watched artifacts")).toBeDefined();
    });

    it("mentions drift only when there is some", () => {
        const quiet = render(() => <HomeBand />);
        expect(quiet.queryByText("0 drift events")).toBeNull();
        quiet.unmount();

        setCounts(1, 0, 2);
        const noisy = render(() => <HomeBand />);
        expect(noisy.getByText("2 drift events")).toBeDefined();
    });

    it("omits a figure whose query has not answered rather than showing zero", () => {
        vi.mocked(useMyNamespaces).mockReturnValue(
            pending as unknown as ReturnType<typeof useMyNamespaces>,
        );
        const { queryByText, getByText } = render(() => <HomeBand />);
        expect(queryByText("0 namespaces")).toBeNull();
        // The band still renders — one pending query must not blank the rest.
        expect(getByText("Welcome back, octocat")).toBeDefined();
    });
});
