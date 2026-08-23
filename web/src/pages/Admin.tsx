import { Show, type JSX } from "solid-js";
import { useLocation } from "@solidjs/router";
import { useAuth } from "~/context/auth";
import { SkeletonHeader } from "~/components/Skeleton";
import { UsersTab } from "./admin/UsersTab";
import { APIKeysTab } from "./admin/APIKeysTab";
import { StatusTab } from "./admin/StatusTab";
import { SourcesTab } from "./admin/SourcesTab";
import { NamespacesTab } from "./admin/NamespacesTab";
import { JobsTab } from "./admin/JobsTab";
import { PageHeader, TabBar } from "~/components/ui";
import type { TabDef } from "~/components/ui";

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
    // The href doubles as the tab id: it is unique per tab and is what the
    // strip navigates to anyway.
    const tabDefs = (): TabDef<string>[] =>
        tabs().map((t) => ({ id: t.href, label: t.label, href: t.href }));

    // Held until the session resolves. Rendering early produced a tab strip and
    // a panel computed from different values of `tabs()`: the strip re-derived
    // itself when `user()` arrived, but the panel below was mounted by a
    // non-keyed <Show> whose children function never re-ran, so /admin/jobs
    // highlighted Jobs and rendered Sources forever (ocidex-ag4q.5).
    return (
        <Show when={!user.loading} fallback={<SkeletonHeader />}>
            <PageHeader
                title={user()?.role === "admin" ? "Admin" : "Sources"}
                subtitle={
                    user()?.role === "admin"
                        ? "User management, API keys, and system configuration"
                        : "Registries and other ingest channels you own"
                }
            />

            {/* The strip is <TabBar> rather than a hand-rolled <nav> of inline
                styles, so /admin looks like every other tab strip in the app.
                The tabs stay links — they are routes, not local state. */}
            <TabBar
                tabs={tabDefs()}
                active={active().href}
                class="mb-4"
            />

            {/* `keyed` is load-bearing: without it the children function runs
                once and the panel is frozen at whichever tab was active on
                mount, even as the strip above tracks the route. */}
            <Show when={active()} keyed>
                {(tab) => tab.render()}
            </Show>
        </Show>
    );
}
