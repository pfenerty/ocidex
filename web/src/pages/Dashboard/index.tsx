import { For, Show, type JSX } from "solid-js";
import { useAuth } from "~/context/auth";
import {
    NamespacesPanel,
    IngestPanel,
    DriftPanel,
    ExposurePanel,
    ClustersPanel,
    WatchFeedPanel,
} from "./panels";
import "./Dashboard.css";
import { PageHeader } from "~/components/ui";

interface Section {
    /** Stable key; also what a future per-section preference would be keyed by. */
    id: string;
    /** True for sections whose rows carry enough text to want the full width. */
    wide?: boolean;
    /**
     * What kind of thing this panel is. "alert" panels report something wrong
     * and are ordered first; "inventory" panels describe what exists and stay
     * quiet. Without the distinction a provenance-drift regression rendered
     * with exactly the weight of a list of namespaces (ocidex-ag4q.40).
     *
     * The ordering is not purely static: an alert panel that has nothing to
     * report sinks below the inventory (see Dashboard.css), so the page leads
     * with whatever is actually wrong rather than with the alarm's own header.
     */
    tone: "alert" | "inventory";
    render: () => JSX.Element;
}

/**
 * SECTIONS is the dashboard's extension point: one entry here and one panel
 * component is the whole cost of a new section — the grid is auto-fill (see
 * Dashboard.css), so nothing about the layout has to change, and ordering is a
 * property of this list rather than of the JSX below. The clusters section
 * (ocidex-zeta.6) was added exactly that way.
 */
const SECTIONS: Section[] = [
    { id: "drift", tone: "alert", render: () => <DriftPanel /> },
    { id: "exposure", tone: "alert", render: () => <ExposurePanel /> },
    { id: "namespaces", tone: "inventory", render: () => <NamespacesPanel /> },
    { id: "ingest", tone: "inventory", render: () => <IngestPanel /> },
    { id: "clusters", tone: "inventory", render: () => <ClustersPanel /> },
    { id: "watch-feed", tone: "inventory", wide: true, render: () => <WatchFeedPanel /> },
];

/**
 * Dashboard is the signed-in workspace: everything the caller owns or follows,
 * on one page, each panel a preview that links through to the page that owns
 * the data in full.
 *
 * Every panel reads a /users/me/* endpoint, so the page needs no role check —
 * an unauthenticated caller would get 401s from all of them. Layout redirects
 * that case to /login before this component renders; the fallback here covers
 * the moment before the session resource resolves.
 */
export default function Dashboard(): JSX.Element {
    const { user } = useAuth();

    return (
        <>
            <PageHeader
                title="Workspace"
                subtitle={
                    <Show when={user()} fallback="Your namespaces, ingests and alerts">
                        {(u) => `Signed in as ${u().github_username}`}
                    </Show>
                }
            />

            <div class="dash-grid">
                <For each={SECTIONS}>
                    {(section) => (
                        <div
                            data-section={section.id}
                            class={[
                                "dash-section",
                                `dash-section-${section.tone}`,
                                section.wide === true ? "dash-section-wide" : "",
                            ]
                                .filter((c) => c !== "")
                                .join(" ")}
                        >
                            {section.render()}
                        </div>
                    )}
                </For>
            </div>
        </>
    );
}
