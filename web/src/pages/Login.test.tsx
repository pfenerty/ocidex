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

describe("Login", () => {
    it("renders the OCIDex brand heading", () => {
        const { getByRole } = render(() => <Login />);
        const heading = getByRole("heading", { level: 1 });
        expect(heading.textContent).toBe("OCIDex");
    });

    it("renders a GitHub OAuth link pointing to /auth/login", () => {
        const { getByRole } = render(() => <Login />);
        const link = getByRole("link");
        expect(link.getAttribute("href")).toBe("http://api.test/auth/login");
    });

    it("renders the sign-in prompt text", () => {
        const { getByText } = render(() => <Login />);
        expect(getByText("Sign in to access the dashboard")).toBeDefined();
    });

    it("renders GitHub button label", () => {
        const { getByText } = render(() => <Login />);
        expect(getByText("Continue with GitHub")).toBeDefined();
    });
});
