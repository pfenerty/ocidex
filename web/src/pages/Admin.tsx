import { Show, For, type JSX } from "solid-js";
import { useLocation, A } from "@solidjs/router";
import { useAuth } from "~/context/auth";
import { SkeletonHeader } from "~/components/Skeleton";
import { UsersTab } from "./admin/UsersTab";
import { APIKeysTab } from "./admin/APIKeysTab";
import { StatusTab } from "./admin/StatusTab";
import { SourcesTab } from "./admin/SourcesTab";
import { NamespacesTab } from "./admin/NamespacesTab";
import { JobsTab } from "./admin/JobsTab";

interface AdminTab {
    label: string;
    href: string;
    /** Every path that should light this tab up, including legacy ones. */
    paths: string[];
    /**
     * True when every endpoint behind the tab requires the admin role.
     *
     * Sources is the exception: creating a registry is `authenticated` and
     * editing one is `owner`, so a namespace owner can use that tab in full.
     * It lives here only because this is where it was first built, and the
     * cluster Gaps tab has to be able to send them to it.
     */
    adminOnly: boolean;
    render: () => JSX.Element;
}

const TABS: AdminTab[] = [
    { label: "Users", href: "/admin", paths: ["/admin"], adminOnly: true, render: () => <UsersTab /> },
    { label: "API Keys", href: "/admin/keys", paths: ["/admin/keys"], adminOnly: true, render: () => <APIKeysTab /> },
    {
        label: "Namespaces",
        href: "/admin/namespaces",
        paths: ["/admin/namespaces"],
        adminOnly: true,
        render: () => <NamespacesTab />,
    },
    {
        label: "Sources",
        href: "/admin/sources",
        // /admin/registries stays a live path: the tab was called Registries
        // until ADR-039 split that concept, and bookmarks should not 404.
        paths: ["/admin/sources", "/admin/registries"],
        adminOnly: false,
        render: () => <SourcesTab />,
    },
    { label: "System Status", href: "/admin/status", paths: ["/admin/status"], adminOnly: true, render: () => <StatusTab /> },
    { label: "Jobs", href: "/admin/jobs", paths: ["/admin/jobs"], adminOnly: true, render: () => <JobsTab /> },
];

export default function Admin() {
    const location = useLocation();
    const { user } = useAuth();
    // A non-admin sees only the tabs they can actually use. Showing the other
    // five would offer them a row of 403s.
    //
    // This is role-dependent, so it is wrong while the session is still in
    // flight: `user()` is undefined during the first paint and every visitor
    // would briefly read as a non-admin. Nothing below renders until the
    // session resolves — see the loading gate on the return.
    const tabs = () => (user()?.role === "admin" ? TABS : TABS.filter((t) => !t.adminOnly));
    // A non-admin who lands on an admin-only path (a stale bookmark, a shared
    // link) gets the tabs they do have rather than an empty page — the tab strip
    // already tells them which one they are on.
    const active = () => tabs().find((t) => t.paths.includes(location.pathname)) ?? tabs()[0];
    const isActive = (tab: AdminTab) => tab === active();

    // Held until the session resolves. Rendering early produced a tab strip and
    // a panel computed from different values of `tabs()`: the strip re-derived
    // itself when `user()` arrived, but the panel below was mounted by a
    // non-keyed <Show> whose children function never re-ran, so /admin/jobs
    // highlighted Jobs and rendered Sources forever (ocidex-ag4q.5).
    return (
        <Show when={!user.loading} fallback={<SkeletonHeader />}>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>{user()?.role === "admin" ? "Admin" : "Sources"}</h2>
                        <p>
                            {user()?.role === "admin"
                                ? "User management, API keys, and system configuration"
                                : "Registries and other ingest channels you own"}
                        </p>
                    </div>
                </div>
            </div>

            <nav style={{ display: "flex", gap: "0", "margin-bottom": "1.5rem", "border-bottom": "1px solid var(--color-border)" }}>
                <For each={tabs()}>
                    {(tab) => (
                        <A
                            href={tab.href}
                            style={{
                                padding: "0.5rem 1rem",
                                "border-bottom": isActive(tab) ? "2px solid var(--color-primary)" : "2px solid transparent",
                                color: isActive(tab) ? "var(--color-primary)" : "inherit",
                                "font-weight": isActive(tab) ? "600" : "400",
                                "margin-bottom": "-1px",
                            }}
                        >
                            {tab.label}
                        </A>
                    )}
                </For>
            </nav>

            {/* `keyed` is load-bearing: without it the children function runs
                once and the panel is frozen at whichever tab was active on
                mount, even as the strip above tracks the route. */}
            <Show when={active()} keyed>
                {(tab) => tab.render()}
            </Show>
        </Show>
    );
}
