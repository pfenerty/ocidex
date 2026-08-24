import { createSignal, Show, For } from "solid-js";
import "./ChangelogTab.css";
import type { ChangelogEntryData } from "~/utils/diff";
import { ViewToggle } from "~/components/DiffPairView";
import { DiffEntryCard } from "~/components/DiffEntryCard";
import { EmptyState } from "~/components/Feedback";
import { TabBar } from "~/components/ui";

export function ChangelogTab(props: {
    entries: ChangelogEntryData[];
    availableArchitectures: string[];
    selectedArch: string | undefined;
    onArchChange: (arch: string) => void;
    availableFlavors: string[];
    selectedFlavor: string | undefined;
    onFlavorChange: (flavor: string) => void;
}) {
    const effectiveArch = () =>
        props.selectedArch ?? props.availableArchitectures[0];
    const effectiveFlavor = () =>
        props.selectedFlavor ?? props.availableFlavors[0];
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");

    return (
        <>
            <div
                style={{
                    display: "flex",
                    "align-items": "flex-start",
                    gap: "0.75rem",
                    "margin-bottom": "1rem",
                }}
            >
                <div style={{ flex: "1", display: "flex", "flex-direction": "column", gap: "0.5rem", "min-width": "0" }}>
                    <Show when={props.availableArchitectures.length > 1}>
                        <TabBar
                            variant="filter"
                            label="Architecture"
                            tabs={props.availableArchitectures.map((a) => ({ id: a, label: a }))}
                            active={effectiveArch()}
                            onSelect={props.onArchChange}
                        />
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
                </div>
                <ViewToggle mode={viewMode()} onChange={setViewMode} />
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
                            viewMode={viewMode()}
                            defaultExpanded={false}
                        />
                    )}
                </For>
            </Show>
        </>
    );
}
