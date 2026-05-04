import { createSignal, Show, For } from "solid-js";
import type { ChangelogEntryData } from "~/utils/diff";
import { DiffPairView, ViewToggle } from "~/components/DiffPairView";

export function ChangelogTab(props: {
    entries: ChangelogEntryData[];
    availableArchitectures: string[];
    selectedArch: string | undefined;
    onArchChange: (arch: string) => void;
}) {
    const effectiveArch = () =>
        props.selectedArch ?? props.availableArchitectures[0];
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
