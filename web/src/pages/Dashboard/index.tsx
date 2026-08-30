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
import { roleEmphasis, type Emphasis } from "~/utils/emphasis";

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
 * Per-emphasis lead order (ocidex-y0hg.9). Each entry lists the sections that
 * go first for that kind of caller; anything not named keeps its SECTIONS
 * order behind them.
 *
 * Every emphasis renders every section — this list is a permutation, never a
 * filter. `orderFor` asserts that by construction: it appends the remainder
 * rather than taking the lead list as the answer, so a section added to
 * SECTIONS and forgotten here still renders.
 *
 * "balanced" is absent on purpose: an owner, a maintainer, a viewer and a
 * mixed caller all get SECTIONS as written, which is the ordering the page
 * shipped with (alarms first, then inventory).
 */
const LEAD: Record<Exclude<Emphasis, "balanced">, readonly string[]> = {
    // Someone whose namespaces are mostly 'security' is here for what is
    // wrong: drift, then exposure, then the cluster workloads that could not
    // be resolved back to an artifact (ADR-044).
    security: ["drift", "exposure", "clusters"],
    // Someone whose namespaces are mostly 'developer' is here for what they
    // just shipped: recent ingests and the scans behind them, then their own
    // namespaces. The alarms follow immediately — they are demoted, not
    // buried.
    developer: ["ingest", "namespaces"],
};

/** SECTIONS reordered for an emphasis, with every section still present. */
function orderFor(emphasis: Emphasis): Section[] {
    if (emphasis === "balanced") return SECTIONS;
    const lead = LEAD[emphasis];
    const led = lead
        .map((id) => SECTIONS.find((s) => s.id === id))
        .filter((s): s is Section => s !== undefined);
    return [...led, ...SECTIONS.filter((s) => !led.includes(s))];
}

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

    // Which panels lead is a property of the caller's namespace roles, not of
    // what they are allowed to fetch: every panel below is rendered for every
    // caller, and every one of them reads a /users/me/* endpoint that has
    // already decided what this caller may see.
    const emphasis = () => roleEmphasis(user()?.memberships);

    return (
        <>
            <PageHeader
                title="Workspace"
                subtitle={
                    <Show when={user()} fallback="Your namespaces, ingests and alerts">
                        {(u) => `Signed in as ${u().display_name}`}
                    </Show>
                }
            />

            <div class="dash-grid" data-emphasis={emphasis()}>
                <For each={orderFor(emphasis())}>
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
