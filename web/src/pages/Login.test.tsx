// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import Login from "~/pages/Login";

vi.mock("~/api/client", () => ({
    API_BASE_URL: "http://api.test",
    client: {},
    APIClientError: class extends Error {},
    unwrap: vi.fn(),
}));

interface Provider {
    name: string;
    display_name: string;
    login_path: string;
}

interface ProvidersQuery {
    data?: { providers: Provider[] };
    isPending: boolean;
    isError: boolean;
}

const providersResult = vi.fn<() => ProvidersQuery>();

vi.mock("~/api/queries", () => ({
    useAuthProviders: () => providersResult(),
}));

function withProviders(providers: Provider[]) {
    providersResult.mockReturnValue({
        data: { providers },
        isPending: false,
        isError: false,
    });
}

const github: Provider = {
    name: "github",
    display_name: "GitHub",
    login_path: "/auth/login/github",
};

const corp: Provider = {
    name: "oidc:corp",
    display_name: "corp",
    login_path: "/auth/login/oidc:corp",
};

describe("Login", () => {
    it("renders the OCIDex brand heading", () => {
        withProviders([github]);
        const { getByRole } = render(() => <Login />);
        const heading = getByRole("heading", { level: 1 });
        expect(heading.textContent).toBe("OCIDex");
    });

    it("renders the sign-in prompt text", () => {
        withProviders([github]);
        const { getByText } = render(() => <Login />);
        expect(getByText("Sign in to access the dashboard")).toBeDefined();
    });

    // The single-provider case is what almost every installation is, and it has
    // to keep looking like the button that was hardcoded here before.
    it("renders one link per provider, pointing at that provider's login path", () => {
        withProviders([github]);
        const { getAllByRole } = render(() => <Login />);
        const links = getAllByRole("link");
        expect(links).toHaveLength(1);
        expect(links[0].getAttribute("href")).toBe("http://api.test/auth/login/github");
        expect(links[0].textContent).toContain("Continue with GitHub");
    });

    it("renders a button for every configured issuer", () => {
        withProviders([github, corp]);
        const { getAllByRole } = render(() => <Login />);
        const links = getAllByRole("link");
        expect(links).toHaveLength(2);
        expect(links[1].getAttribute("href")).toBe("http://api.test/auth/login/oidc:corp");
        expect(links[1].textContent).toContain("Continue with corp");
    });

    // A deployment with no issuer configured cannot be signed in to. Saying so
    // beats a page with an empty space where the button was.
    it("says so when no issuer is configured", () => {
        withProviders([]);
        const { getByText, queryAllByRole } = render(() => <Login />);
        expect(queryAllByRole("link")).toHaveLength(0);
        expect(getByText("No sign-in method is configured on this deployment.")).toBeDefined();
    });

    it("says so when the provider list cannot be fetched", () => {
        providersResult.mockReturnValue({ data: undefined, isPending: false, isError: true });
        const { getByText } = render(() => <Login />);
        expect(getByText("Sign-in is unavailable — could not reach the API.")).toBeDefined();
    });
});
