import { Show, For, type JSX } from "solid-js";
import { useLocation, A } from "@solidjs/router";
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
    render: () => JSX.Element;
}

const TABS: AdminTab[] = [
    { label: "Users", href: "/admin", paths: ["/admin"], render: () => <UsersTab /> },
    { label: "API Keys", href: "/admin/keys", paths: ["/admin/keys"], render: () => <APIKeysTab /> },
    {
        label: "Namespaces",
        href: "/admin/namespaces",
        paths: ["/admin/namespaces"],
        render: () => <NamespacesTab />,
    },
    {
        label: "Sources",
        href: "/admin/sources",
        // /admin/registries stays a live path: the tab was called Registries
        // until ADR-039 split that concept, and bookmarks should not 404.
        paths: ["/admin/sources", "/admin/registries"],
        render: () => <SourcesTab />,
    },
    { label: "System Status", href: "/admin/status", paths: ["/admin/status"], render: () => <StatusTab /> },
    { label: "Jobs", href: "/admin/jobs", paths: ["/admin/jobs"], render: () => <JobsTab /> },
];

export default function Admin() {
    const location = useLocation();
    const isActive = (tab: AdminTab) => tab.paths.includes(location.pathname);

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Admin</h2>
                        <p>User management, API keys, and system configuration</p>
                    </div>
                </div>
            </div>

            <nav style={{ display: "flex", gap: "0", "margin-bottom": "1.5rem", "border-bottom": "1px solid var(--color-border)" }}>
                <For each={TABS}>
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

            <For each={TABS}>{(tab) => <Show when={isActive(tab)}>{tab.render()}</Show>}</For>
        </>
    );
}
