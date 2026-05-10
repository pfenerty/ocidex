import { createSignal, Show, For } from "solid-js";
import "./ChangelogTab.css";
import type { ChangelogEntryData } from "~/utils/diff";
import { DiffPairView, ViewToggle } from "~/components/DiffPairView";

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
                    "align-items": "center",
                    gap: "0.75rem",
                    "margin-bottom": "1rem",
                    "flex-wrap": "wrap",
                }}
            >
                <Show when={props.availableArchitectures.length > 1}>
                    <div class="tab-bar" style={{ flex: "1" }}>
                        <For each={props.availableArchitectures}>
                            {(arch) => (
                                <button
                                    class={effectiveArch() === arch ? "active" : ""}
                                    onClick={() => props.onArchChange(arch)}
                                >
                                    {arch}
                                </button>
                            )}
                        </For>
                    </div>
                </Show>
                <Show when={props.availableFlavors.length > 1}>
                    <div class="tab-bar" style={{ flex: "1" }}>
                        <For each={props.availableFlavors}>
                            {(flavor) => (
                                <button
                                    class={effectiveFlavor() === flavor ? "active" : ""}
                                    onClick={() => props.onFlavorChange(flavor)}
                                >
                                    {flavor}
                                </button>
                            )}
                        </For>
                    </div>
                </Show>
                <div style={{ "margin-left": "auto" }}>
                    <ViewToggle mode={viewMode()} onChange={setViewMode} />
                </div>
            </div>
            <For each={props.entries}>
                {(entry) => (
                    <DiffPairView
                        fromId={entry.from.id}
                        toId={entry.to.id}
                        viewMode={viewMode()}
                    />
                )}
            </For>
        </>
    );
}
