import { Show, For, createSignal, type JSX } from "solid-js";
import "./ChangelogTab.css";
import type { ChangelogEntryData } from "~/utils/diff";
import type { PaginationMeta } from "~/api/client";
import { ViewToggle } from "~/components/DiffPairView";
import { CveEntryCard } from "./CveEntryCard";
import { EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { TabBar } from "~/components/ui";
import { Combobox } from "~/components/ui/Combobox";

/** Above this many architectures the pills become a picker. */
const MAX_ARCH_PILLS = 4;

/** Where the viewer's "only CVE rows" choice is kept, per browser. */
export const CVE_ONLY_KEY = "ocidex.changelog.cveOnly";

/** The viewer's stored choice; on unless they turned it off. */
export function readCveOnly(): boolean {
    try {
        return localStorage.getItem(CVE_ONLY_KEY) !== "false";
    } catch {
        return true;
    }
}

function writeCveOnly(on: boolean): void {
    try {
        localStorage.setItem(CVE_ONLY_KEY, String(on));
    } catch {
        // Storage blocked: the choice lasts for this page only.
    }
}

// The changelog is a page of a longer timeline, not the whole of it
// (ocidex-7gf7.4). Both the page and the tree/list mode are owned by the parent:
// QueryBoundary renders this component under <Show keyed>, so turning the page
// remounts it and any state held here would reset.
export function ChangelogTab(props: {
    entries: ChangelogEntryData[];
    pagination: PaginationMeta | undefined;
    onPageChange: (offset: number) => void;
    availableArchitectures: string[];
    selectedArch: string | undefined;
    onArchChange: (arch: string) => void;
    availableFlavors: string[];
    selectedFlavor: string | undefined;
    onFlavorChange: (flavor: string) => void;
    viewMode: "tree" | "list";
    onViewModeChange: (mode: "tree" | "list") => void;
    /** The page's version-order control, placed on the same row as the rest. */
    order?: JSX.Element;
}) {
    const effectiveArch = () =>
        props.selectedArch ?? props.availableArchitectures[0];
    const effectiveFlavor = () =>
        props.selectedFlavor ?? props.availableFlavors[0];
    const [cveOnly, setCveOnly] = createSignal(readCveOnly());
    const toggleCveOnly = (on: boolean) => {
        setCveOnly(on);
        writeCveOnly(on);
    };

    return (
        <>
            {/* One row for every control that shapes one entry: order, then
                architecture and flavor, then tree or list. Three rows of
                controls pushed the first entry down for nothing. */}
            <div class="changelog-controls">
                {props.order}
                <Show when={props.availableArchitectures.length > 1}>
                    {/* Pills scan well up to a handful; past that they wrap
                        into a block of their own, so they become a picker. */}
                    <Show
                        when={props.availableArchitectures.length > MAX_ARCH_PILLS}
                        fallback={
                            <TabBar
                                variant="filter"
                                label="Architecture"
                                tabs={props.availableArchitectures.map((a) => ({ id: a, label: a }))}
                                active={effectiveArch()}
                                onSelect={props.onArchChange}
                            />
                        }
                    >
                        <Combobox
                            class="changelog-arch-picker"
                            label="Architecture"
                            items={props.availableArchitectures}
                            value={effectiveArch()}
                            onSelect={props.onArchChange}
                            itemId={(a) => a}
                            itemLabel={(a) => a}
                        />
                    </Show>
                </Show>
                <Show when={props.availableFlavors.length > 1}>
                    <TabBar
                        variant="filter"
                        label="Flavor"
                        tabs={props.availableFlavors.map((f) => ({ id: f, label: f }))}
                        active={effectiveFlavor()}
                        onSelect={props.onFlavorChange}
                    />
                </Show>
                <label class="changelog-cve-only">
                    <input
                        type="checkbox"
                        checked={cveOnly()}
                        onChange={(ev) => toggleCveOnly(ev.currentTarget.checked)}
                    />
                    Only package changes that close or open a CVE
                </label>
                <span class="changelog-controls-end">
                    <span class="cve-legend">
                        <span>
                            <span class="cve-sw cve-sw-critical" /> closed
                        </span>
                        <span>
                            <span class="cve-sw cve-sw-opened" /> opened
                        </span>
                    </span>
                    <Show when={!cveOnly()}>
                        <ViewToggle mode={props.viewMode} onChange={props.onViewModeChange} />
                    </Show>
                </span>
            </div>
            <Show
                when={props.entries.length > 0}
                fallback={
                    // The architecture wording only makes sense when an
                    // architecture selector is actually on screen — a non-container
                    // artifact has no arch to switch to.
                    <Show
                        when={props.availableArchitectures.length > 1}
                        fallback={
                            <EmptyState
                                title="No changes yet"
                                message="Ingest another SBOM for this artifact to generate a diff."
                            />
                        }
                    >
                        <EmptyState
                            title="No changes for this architecture"
                            message="Select a different architecture to see changelog entries, or ingest another SBOM to generate a diff."
                        />
                    </Show>
                }
            >
                <For each={props.entries}>
                    {(entry) => (
                        <CveEntryCard entry={entry} cveOnly={cveOnly()} viewMode={props.viewMode} />
                    )}
                </For>
                <Show when={props.pagination}>
                    {(meta) => (
                        <Pagination pagination={meta()} onPageChange={props.onPageChange} />
                    )}
                </Show>
            </Show>
        </>
    );
}
