import { For, Show, type JSX } from "solid-js";
import { useAuth } from "~/context/auth";
import {
    NamespacesPanel,
    IngestPanel,
    DriftPanel,
    ExposurePanel,
    WatchFeedPanel,
} from "./panels";
import "./Dashboard.css";

interface Section {
    /** Stable key; also what a future per-section preference would be keyed by. */
    id: string;
    /** True for sections whose rows carry enough text to want the full width. */
    wide?: boolean;
    render: () => JSX.Element;
}

/**
 * SECTIONS is the dashboard's extension point. Adding the clusters section on
 * the roadmap means adding one entry here and one panel component — the grid is
 * auto-fill (see Dashboard.css), so nothing about the layout has to change, and
 * ordering is a property of this list rather than of the JSX below.
 */
const SECTIONS: Section[] = [
    { id: "namespaces", render: () => <NamespacesPanel /> },
    { id: "ingest", render: () => <IngestPanel /> },
    { id: "drift", render: () => <DriftPanel /> },
    { id: "exposure", render: () => <ExposurePanel /> },
    { id: "watch-feed", wide: true, render: () => <WatchFeedPanel /> },
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
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Workspace</h2>
                        <p>
                            <Show when={user()} fallback="Your namespaces, ingests and alerts">
                                {(u) => `Signed in as ${u().github_username}`}
                            </Show>
                        </p>
                    </div>
                </div>
            </div>

            <div class="dash-grid">
                <For each={SECTIONS}>
                    {(section) => (
                        <div class={section.wide === true ? "dash-section-wide" : undefined}>
                            {section.render()}
                        </div>
                    )}
                </For>
            </div>
        </>
    );
}
