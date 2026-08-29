// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import PersonaSwitcher from "~/components/dev/PersonaSwitcher";

vi.mock("~/api/client", () => ({ API_BASE_URL: "" }));

interface User {
    id: string;
    github_username: string;
    role: string;
}

let mockUser: User | undefined;
vi.mock("~/context/auth", () => ({
    useAuth: () => ({ user: () => mockUser, refetch: vi.fn() }),
}));

// Vitest does not run through vite.config.auth.ts, so the roster define is
// absent here and has to be stubbed. That asymmetry is the point of the
// component's gate: with no roster the switcher renders nothing at all, which
// is exactly what a production build does.
function withRoster(value: string | undefined) {
    vi.stubEnv("VITE_DEV_PERSONAS", value);
}

// A typed lookup rather than `getByLabelText(...) as HTMLSelectElement`: the
// lint autofixer strips that assertion as redundant and then tsc rejects
// `.value` and `.options` on the HTMLElement left behind.
function personaSelect(container: HTMLElement): HTMLSelectElement {
    const el = container.querySelector<HTMLSelectElement>("#persona-select");
    if (el === null) throw new Error("persona select not rendered");
    return el;
}

describe("PersonaSwitcher", () => {
    beforeEach(() => {
        mockUser = undefined;
        vi.restoreAllMocks();
        Object.defineProperty(window, "location", {
            value: { reload: vi.fn() },
            writable: true,
        });
    });

    afterEach(() => {
        vi.unstubAllEnvs();
    });

    it("renders nothing without a roster", () => {
        withRoster(undefined);
        const { queryByTestId } = render(() => <PersonaSwitcher />);
        expect(queryByTestId("persona-switcher")).toBeNull();
    });

    it("lists every seeded persona plus a signed-out option", () => {
        withRoster("devadmin,devowner,devviewer");
        const { container } = render(() => <PersonaSwitcher />);
        const select = personaSelect(container);
        expect([...select.options].map((o) => o.value)).toEqual([
            "",
            "devadmin",
            "devowner",
            "devviewer",
        ]);
    });

    it("selects the current user, so the control shows who you are", () => {
        withRoster("devadmin,devviewer");
        mockUser = { id: "1", github_username: "devviewer", role: "viewer" };
        const { container } = render(() => <PersonaSwitcher />);
        expect(personaSelect(container).value).toBe("devviewer");
    });

    it("mints a session for the chosen persona and reloads", async () => {
        withRoster("devadmin,devviewer");
        const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        vi.stubGlobal("fetch", fetchMock);

        const { container } = render(() => <PersonaSwitcher />);
        const select = personaSelect(container);
        select.value = "devviewer";
        fireEvent.change(select);

        await waitFor(() => expect(fetchMock).toHaveBeenCalled());
        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toBe("/api/v1/dev/session");
        expect(init.method).toBe("POST");
        // credentials:include is load-bearing: the whole point is the Set-Cookie.
        expect(init.credentials).toBe("include");
        expect(init.body).toBe(JSON.stringify({ username: "devviewer" }));
        await waitFor(() => expect(window.location.reload).toHaveBeenCalled());
    });

    // A 404 means the API is not running with ENVIRONMENT=development. Every
    // other part of the rig looks healthy in that state, so the switcher has to
    // say so rather than fail silently.
    it("names the missing mint endpoint rather than reloading", async () => {
        withRoster("devadmin");
        vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 404 }));

        const { container, findByText } = render(() => <PersonaSwitcher />);
        const select = personaSelect(container);
        select.value = "devadmin";
        fireEvent.change(select);

        expect(await findByText("mint endpoint not registered")).toBeTruthy();
        expect(window.location.reload).not.toHaveBeenCalled();
    });
});
