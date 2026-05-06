import { Show } from "solid-js";
import { useLocation, A } from "@solidjs/router";
import { UsersTab } from "./admin/UsersTab";
import { APIKeysTab } from "./admin/APIKeysTab";
import { StatusTab } from "./admin/StatusTab";
import { RegistriesTab } from "./admin/RegistriesTab";
import { JobsTab } from "./admin/JobsTab";
import { MetricsTab } from "./admin/MetricsTab";

export default function Admin() {
    const location = useLocation();

    const isUsersTab = () => location.pathname === "/admin";
    const isKeysTab = () => location.pathname === "/admin/keys";
    const isStatusTab = () => location.pathname === "/admin/status";
    const isRegistriesTab = () => location.pathname === "/admin/registries";
    const isMetricsTab = () => location.pathname === "/admin/metrics";
    const isJobsTab = () => location.pathname === "/admin/jobs";

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
                <A
                    href="/admin"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isUsersTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isUsersTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isUsersTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Users
                </A>
                <A
                    href="/admin/keys"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isKeysTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isKeysTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isKeysTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    API Keys
                </A>
                <A
                    href="/admin/registries"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isRegistriesTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isRegistriesTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isRegistriesTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Registries
                </A>
                <A
                    href="/admin/status"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isStatusTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isStatusTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isStatusTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    System Status
                </A>
                <A
                    href="/admin/metrics"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isMetricsTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isMetricsTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isMetricsTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Metrics
                </A>
                <A
                    href="/admin/jobs"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isJobsTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isJobsTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isJobsTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Jobs
                </A>
            </nav>

            <Show when={isUsersTab()}>
                <UsersTab />
            </Show>
            <Show when={isKeysTab()}>
                <APIKeysTab />
            </Show>
            <Show when={isRegistriesTab()}>
                <RegistriesTab />
            </Show>
            <Show when={isStatusTab()}>
                <StatusTab />
            </Show>
            <Show when={isMetricsTab()}>
                <MetricsTab />
            </Show>
            <Show when={isJobsTab()}>
                <JobsTab />
            </Show>
        </>
    );
}
