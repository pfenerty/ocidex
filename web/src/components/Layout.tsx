import { A } from "@solidjs/router";
import type { ParentProps } from "solid-js";
import ThemeToggle from "~/components/ThemeToggle";

export default function Layout(props: ParentProps) {
    return (
        <div class="layout">
            <aside class="sidebar">
                <div class="sidebar-brand">
                    <h1>
                        OCI<span>Dex</span>
                    </h1>
                    <p>SBOM Explorer</p>
                </div>
                <nav>
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
                </nav>
                <div class="sidebar-footer">
                    <ThemeToggle />
                </div>
            </aside>
            <main class="main-content">{props.children}</main>
        </div>
    );
}
