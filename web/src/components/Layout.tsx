import "./Layout.css";
import { A, useNavigate, useLocation } from "@solidjs/router";
import { createEffect, Show, type ParentProps } from "solid-js";
import { Home, LayoutDashboard, Package, Layers, ShieldCheck, ArrowUpDown, ShieldAlert, Server, Database, Settings, LogOut, Search } from "lucide-solid";
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
            <aside class="sidebar">
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
                <button type="button" class="sidebar-search" onClick={openCommandPalette}>
                    <Search size={14} />
                    <span>Search</span>
                    <kbd>{isAppleShortcut() ? "\u2318K" : "Ctrl K"}</kbd>
                </button>
                <nav>
                    <A href="/" end>
                        <Home size={16} />
                        <span>Home</span>
                    </A>
                    <Show when={user()}>
                        <A href="/dashboard">
                            <LayoutDashboard size={16} />
                            <span>Workspace</span>
                        </A>
                    </Show>
                    <A href="/artifacts">
                        <Package size={16} />
                        <span>Artifacts</span>
                    </A>
                    <A href="/components">
                        <Layers size={16} />
                        <span>Components</span>
                    </A>
                    <A href="/licenses">
                        <ShieldCheck size={16} />
                        <span>Licenses</span>
                    </A>
                    <A href="/vulnerabilities">
                        <ShieldAlert size={16} />
                        <span>Vulnerabilities</span>
                    </A>
                    <A href="/diff">
                        <ArrowUpDown size={16} />
                        <span>Compare</span>
                    </A>
                    <Show when={user()}>
                        <A href="/clusters">
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
                        <A href="/admin/sources">
                            <Database size={16} />
                            <span>Sources</span>
                        </A>
                    </Show>
                    <Show when={user()?.role === "admin"}>
                        <A href="/admin">
                            <Settings size={16} />
                            <span>Admin</span>
                        </A>
                    </Show>
                </nav>
                <div class="sidebar-footer">
                    <ThemeToggle />
                    <Show when={user()} fallback={
                        <A href="/login" class="sidebar-sign-in">
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
