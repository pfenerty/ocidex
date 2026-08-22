// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";
import { createSignal, type JSX } from "solid-js";
import Admin from "~/pages/Admin";

// Each tab panel is stubbed to a single recognizable string: this file is about
// which panel mounts, not what any of them render.
vi.mock("~/pages/admin/UsersTab", () => ({ UsersTab: () => <div>panel:users</div> }));
vi.mock("~/pages/admin/APIKeysTab", () => ({ APIKeysTab: () => <div>panel:keys</div> }));
vi.mock("~/pages/admin/StatusTab", () => ({ StatusTab: () => <div>panel:status</div> }));
vi.mock("~/pages/admin/SourcesTab", () => ({ SourcesTab: () => <div>panel:sources</div> }));
vi.mock("~/pages/admin/NamespacesTab", () => ({ NamespacesTab: () => <div>panel:namespaces</div> }));
vi.mock("~/pages/admin/JobsTab", () => ({ JobsTab: () => <div>panel:jobs</div> }));

const mockLocation = { pathname: "/admin" };
vi.mock("@solidjs/router", () => ({
    useLocation: () => mockLocation,
    A: (props: { href: string; children?: JSX.Element }) => <a href={props.href}>{props.children}</a>,
}));

interface User {
    id: string;
    role: string;
}

// A resource-shaped accessor: `user.loading` is what Admin gates on, and the
// bug only exists while it is true.
let mockUserFn: (() => User | undefined) & { loading: boolean };
vi.mock("~/context/auth", () => ({
    useAuth: () => ({ user: mockUserFn, refetch: vi.fn() }),
}));

function resolved(user?: User) {
    return Object.assign(() => user, { loading: false });
}

describe("Admin", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockLocation.pathname = "/admin";
    });

    // The original defect: on first paint `user()` is undefined, so `tabs()` is
    // the single non-admin tab (Sources) and `active()` falls through to it.
    // The panel was mounted by a non-keyed <Show>, so it stayed Sources forever
    // once the admin session arrived — while the strip corrected itself.
    it("renders the route's panel when the session resolves after first paint", async () => {
        const [user, setUser] = createSignal<User | undefined>(undefined);
        const [loading, setLoading] = createSignal(true);
        // `loading` is a reactive getter, not a fixed property: Admin reads
        // `user.loading` inside a tracking scope, and a plain boolean would
        // never re-run it.
        const accessor = () => user();
        // The accessor IS the reactive source here; it is handed to the
        // component under test rather than read in this scope.
        // eslint-disable-next-line solid/reactivity
        Object.defineProperty(accessor, "loading", { get: () => loading() });
        mockUserFn = accessor as typeof mockUserFn;
        mockLocation.pathname = "/admin/jobs";

        const { container } = render(() => <Admin />);
        // Nothing is committed from a half-known session.
        expect(container.textContent).not.toContain("panel:sources");

        setUser({ id: "u-1", role: "admin" });
        setLoading(false);
        await Promise.resolve();

        expect(container.textContent).toContain("panel:jobs");
        expect(container.textContent).not.toContain("panel:sources");
    });

    it.each([
        ["/admin", "panel:users"],
        ["/admin/keys", "panel:keys"],
        ["/admin/namespaces", "panel:namespaces"],
        ["/admin/sources", "panel:sources"],
        ["/admin/status", "panel:status"],
        ["/admin/jobs", "panel:jobs"],
    ])("cold-loads %s into its own panel", (path, panel) => {
        mockLocation.pathname = path;
        mockUserFn = resolved({ id: "u-1", role: "admin" });

        const { container } = render(() => <Admin />);
        expect(container.textContent).toContain(panel);
    });

    // /admin/registries predates the ADR-039 rename and must still resolve.
    it("keeps the legacy /admin/registries path on the Sources tab", () => {
        mockLocation.pathname = "/admin/registries";
        mockUserFn = resolved({ id: "u-1", role: "admin" });

        const { container } = render(() => <Admin />);
        expect(container.textContent).toContain("panel:sources");
    });

    // A non-admin gets the one tab they can use rather than an empty page, even
    // on an admin-only path.
    it("falls a non-admin back to Sources on an admin-only path", () => {
        mockLocation.pathname = "/admin/jobs";
        mockUserFn = resolved({ id: "u-2", role: "user" });

        const { container } = render(() => <Admin />);
        expect(container.textContent).toContain("panel:sources");
        expect(container.textContent).not.toContain("panel:jobs");
        expect(container.textContent).toContain("Registries and other ingest channels you own");
    });
});
