import { Show, For, type JSX } from "solid-js";
import "./ChangelogTab.css";
import type { ChangelogEntryData } from "~/utils/diff";
import type { PaginationMeta } from "~/api/client";
import { ViewToggle } from "~/components/DiffPairView";
import { DiffEntryCard } from "~/components/DiffEntryCard";
import { EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { TabBar } from "~/components/ui";
import { Combobox } from "~/components/ui/Combobox";

/** Above this many architectures the pills become a picker. */
const MAX_ARCH_PILLS = 4;

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
                <span class="changelog-controls-end">
                    <ViewToggle mode={props.viewMode} onChange={props.onViewModeChange} />
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
                        <DiffEntryCard
                            entry={entry}
                            viewMode={props.viewMode}
                            defaultExpanded={false}
                        />
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
