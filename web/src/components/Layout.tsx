import { A, useNavigate, useLocation } from "@solidjs/router";
import { createEffect, Show, type ParentProps } from "solid-js";
import { Home, Package, Layers, ShieldCheck, ArrowUpDown, Settings, LogOut } from "lucide-solid";
import ThemeToggle from "~/components/ThemeToggle";
import { useAuth } from "~/context/auth";
import { API_BASE_URL } from "~/api/client";

export default function Layout(props: ParentProps) {
    const { user, refetch } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();

    const adminPaths = ["/admin"];
    createEffect(() => {
        if (!user.loading && user() === undefined && adminPaths.some(p => location.pathname.startsWith(p))) {
            navigate("/login", { replace: true });
        }
    });

    async function handleLogout() {
        await fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", credentials: "include" });
        void refetch();
    }

    return (
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
                <nav>
                    <A href="/" end>
                        <Home size={16} />
                        <span>Home</span>
                    </A>
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
                    <A href="/diff">
                        <ArrowUpDown size={16} />
                        <span>Compare</span>
                    </A>
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
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
                            </svg>
                            <span>Sign in with GitHub</span>
                        </A>
                    }>
                        {(u) => (
                        <div class="sidebar-user">
                            <div class="sidebar-user-info">
                                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" class="sidebar-github-icon">
                                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
                                </svg>
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
    );
}
