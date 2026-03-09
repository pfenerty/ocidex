import { A, useNavigate, useLocation } from "@solidjs/router";
import { createEffect, Show, type ParentProps } from "solid-js";
import ThemeToggle from "~/components/ThemeToggle";
import { useAuth } from "~/context/auth";
import { API_BASE_URL } from "~/api/client";

export default function Layout(props: ParentProps) {
    const { user, refetch } = useAuth();
    const navigate = useNavigate();
    const location = useLocation();

    createEffect(() => {
        if (!user.loading && user() === undefined && location.pathname !== "/login") {
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
                    <h1>
                        OCI<span>Dex</span>
                    </h1>
                    <p>SBOM Explorer</p>
                </div>
                <nav>
                    <A href="/" end>
                        <svg
                            width="16"
                            height="16"
                            viewBox="0 0 16 16"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M2 6.5L8 2l6 4.5V14H10v-3H6v3H2V6.5z" />
                        </svg>
                        <span>Home</span>
                    </A>
                    <A href="/artifacts">
                        <svg
                            width="16"
                            height="16"
                            viewBox="0 0 16 16"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <rect x="2" y="2" width="12" height="12" rx="1.5" />
                            <path d="M5.5 6h5M5.5 8.5h5M5.5 11h3" />
                        </svg>
                        <span>Artifacts</span>
                    </A>
                    <A href="/components">
                        <svg
                            width="16"
                            height="16"
                            viewBox="0 0 16 16"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <rect x="1.5" y="1.5" width="5" height="5" rx="1" />
                            <rect x="9.5" y="1.5" width="5" height="5" rx="1" />
                            <rect x="1.5" y="9.5" width="5" height="5" rx="1" />
                            <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
                        </svg>
                        <span>Components</span>
                    </A>
                    <A href="/licenses">
                        <svg
                            width="16"
                            height="16"
                            viewBox="0 0 16 16"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13z" />
                            <path d="M5.5 8.5L7 10l3.5-4" />
                        </svg>
                        <span>Licenses</span>
                    </A>
                    <A href="/diff">
                        <svg
                            width="16"
                            height="16"
                            viewBox="0 0 16 16"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M8 1.5v13M1.5 5l3-3 3 3M9.5 11l3 3 3-3" />
                        </svg>
                        <span>Compare</span>
                    </A>
                    <Show when={user()?.role === "admin"}>
                        <A href="/admin">
                            <svg
                                width="16"
                                height="16"
                                viewBox="0 0 16 16"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="1.5"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                            >
                                <path d="M8 1.5a2 2 0 100 4 2 2 0 000-4z" />
                                <path d="M8 7.5C4.5 7.5 2 9.5 2 11v1h12v-1c0-1.5-2.5-3.5-6-3.5z" />
                                <path d="M13 5.5l1.5 1.5-1.5 1.5M11 9l1.5-1.5L14 9" />
                            </svg>
                            <span>Admin</span>
                        </A>
                    </Show>
                </nav>
                <div class="sidebar-footer">
                    <ThemeToggle />
                    <Show when={user()}>
                        {(u) => (
                        <div class="flex items-center justify-between gap-2 mt-2 text-sm">
                            <span class="truncate opacity-70">{u().github_username}</span>
                            <button
                                onClick={() => void handleLogout()}
                                class="opacity-50 hover:opacity-100 transition-opacity"
                                title="Sign out"
                            >
                                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M6 2H3a1 1 0 00-1 1v10a1 1 0 001 1h3M10 11l3-3-3-3M13 8H6" />
                                </svg>
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
