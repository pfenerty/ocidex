import "./Layout.css";
import { A, useNavigate, useLocation } from "@solidjs/router";
import { createEffect, createSignal, onCleanup, onMount, Show, type ParentProps } from "solid-js";
import { Home, LayoutDashboard, Package, Layers, ShieldCheck, ArrowUpDown, ShieldAlert, Server, Database, Settings, LogOut, Search, Menu, X } from "lucide-solid";
import ThemeToggle from "~/components/ThemeToggle";
import CommandPalette, { openCommandPalette, isAppleShortcut } from "~/components/CommandPalette";
import { GitHubMark } from "./icons/GitHubMark";
import { useAuth } from "~/context/auth";
import { API_BASE_URL } from "~/api/client";

export default function Layout(props: ParentProps) {
    const { user, refetch } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();

    // Paths whose every request is authenticated: /admin's surfaces and the
    // /dashboard workspace, which is built entirely from /users/me/* endpoints
    // and would render five 401s to a signed-out visitor.
    //
    // /clusters is here for a sharper reason than convenience: its namespace
    // picker reads /users/me/namespaces, and a 401 anywhere makes the API client
    // hard-navigate to /login (see unwrap). Redirecting up front is the same
    // destination without the flash of a half-rendered page.
    const authedPaths = ["/admin", "/dashboard", "/clusters"];
    createEffect(() => {
        if (!user.loading && user() === undefined && authedPaths.some(p => location.pathname.startsWith(p))) {
            navigate("/login", { replace: true });
        }
    });

    // Below 768px the sidebar is a 56px icon rail, and this opens it back up
    // into a full-width drawer over the content. It is deliberately the *same*
    // sidebar rather than a second copy of the nav: one set of links, one
    // footer, one place for a route to be added. The rail hides the labels with
    // `display: none`, so the open drawer is the element in its natural state.
    const [drawerOpen, setDrawerOpen] = createSignal(false);
    const closeDrawer = () => setDrawerOpen(false);

    // Any navigation closes it. Watching the path rather than putting an
    // onClick on each link also covers the browser Back button and the command
    // palette, both of which can move the page out from under an open drawer.
    createEffect(() => {
        void location.pathname;
        closeDrawer();
    });

    onMount(() => {
        const onKeyDown = (e: KeyboardEvent) => {
            if (e.key === "Escape") closeDrawer();
        };
        window.addEventListener("keydown", onKeyDown);
        onCleanup(() => window.removeEventListener("keydown", onKeyDown));
    });

    async function handleLogout() {
        await fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", credentials: "include" });
        void refetch();
    }

    return (
        <>
        {/* Outside the /login branch on purpose: the shortcut is muscle memory
            or it is nothing, so it may not blink out on one route. */}
        <CommandPalette />
        <Show when={location.pathname !== "/login"} fallback={<>{props.children}</>}>
        <div class="layout">
            {/* Only ever visible under the drawer — see `.sidebar-backdrop`. It
                catches the tap that closes the drawer and, more importantly,
                stops that tap from also activating whatever it landed on. */}
            <Show when={drawerOpen()}>
                <div class="sidebar-backdrop" onClick={closeDrawer} />
            </Show>
            <aside class="sidebar" classList={{ "sidebar-open": drawerOpen() }}>
                {/* Hidden above the breakpoint, where nothing is collapsed. */}
                <button
                    type="button"
                    class="sidebar-drawer-toggle"
                    aria-label={drawerOpen() ? "Close navigation" : "Open navigation"}
                    aria-expanded={drawerOpen()}
                    onClick={() => setDrawerOpen((o) => !o)}
                >
                    {drawerOpen() ? <X size={18} /> : <Menu size={18} />}
                </button>
                <div class="sidebar-brand">
                    <div class="sidebar-brand-title">
                        <span class="brand-led" aria-hidden="true" />
                        <h1 class="brand">
                            OCI<span>Dex</span>
                        </h1>
                    </div>
                    <p>SBOM Explorer</p>
                </div>
                {/* The palette's own door. A shortcut nobody is told about is a
                    shortcut nobody uses. */}
                <button type="button" class="sidebar-search" aria-label="Search" onClick={openCommandPalette}>
                    <Search size={14} />
                    <span>Search</span>
                    <kbd>{isAppleShortcut() ? "\u2318K" : "Ctrl K"}</kbd>
                </button>
                <nav>
                    <A href="/" end aria-label="Home">
                        <Home size={16} />
                        <span>Home</span>
                    </A>
                    <Show when={user()}>
                        <A href="/dashboard" aria-label="Workspace">
                            <LayoutDashboard size={16} />
                            <span>Workspace</span>
                        </A>
                    </Show>
                    <A href="/artifacts" aria-label="Artifacts">
                        <Package size={16} />
                        <span>Artifacts</span>
                    </A>
                    <A href="/components" aria-label="Components">
                        <Layers size={16} />
                        <span>Components</span>
                    </A>
                    <A href="/licenses" aria-label="Licenses">
                        <ShieldCheck size={16} />
                        <span>Licenses</span>
                    </A>
                    <A href="/vulnerabilities" aria-label="Vulnerabilities">
                        <ShieldAlert size={16} />
                        <span>Vulnerabilities</span>
                    </A>
                    <A href="/diff" aria-label="Compare">
                        <ArrowUpDown size={16} />
                        <span>Compare</span>
                    </A>
                    <Show when={user()}>
                        <A href="/clusters" aria-label="Clusters">
                            <Server size={16} />
                            <span>Clusters</span>
                        </A>
                    </Show>
                    {/* Registries are managed on the Sources tab, which lives
                        under /admin for historical reasons only: creating one
                        is `authenticated` and editing one is `owner`, so a
                        namespace owner is allowed to manage registries and
                        simply had no route to the page. Admins keep reaching it
                        through Admin, where the rest of the tabs are. */}
                    <Show when={user() !== undefined && user()?.role !== "admin"}>
                        <A href="/admin/sources" aria-label="Sources">
                            <Database size={16} />
                            <span>Sources</span>
                        </A>
                    </Show>
                    <Show when={user()?.role === "admin"}>
                        <A href="/admin" aria-label="Admin">
                            <Settings size={16} />
                            <span>Admin</span>
                        </A>
                    </Show>
                </nav>
                <div class="sidebar-footer">
                    <ThemeToggle />
                    <Show when={user()} fallback={
                        <A href="/login" class="sidebar-sign-in" aria-label="Sign in with GitHub">
                            <GitHubMark />
                            <span>Sign in with GitHub</span>
                        </A>
                    }>
                        {(u) => (
                        <div class="sidebar-user">
                            <div class="sidebar-user-info">
                                <GitHubMark size={14} class="sidebar-github-icon" />
                                <span class="truncate">{u().github_username}</span>
                            </div>
                            <button
                                onClick={() => void handleLogout()}
                                class="sidebar-logout-btn"
                                title="Sign out"
                            >
                                <LogOut size={14} />
                            </button>
                        </div>
                        )}
                    </Show>
                </div>
            </aside>
            <main class="main-content">{props.children}</main>
        </div>
        </Show>
        </>
    );
}
