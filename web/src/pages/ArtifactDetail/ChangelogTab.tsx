import { createSignal, Show, For } from "solid-js";
import type { ChangelogEntryData } from "~/utils/diff";
import DiffEntry from "~/components/DiffEntry";

export function ChangelogTab(props: {
    entries: ChangelogEntryData[];
    availableArchitectures: string[];
    selectedArch: string | undefined;
    onArchChange: (arch: string) => void;
}) {
    const effectiveArch = () =>
        props.selectedArch ?? props.availableArchitectures[0];
    const [packagesOnly, setPackagesOnly] = createSignal(true);
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter, setNameFilter] = createSignal("");
    const toggleTypeFilter = (kind: string) =>
        setTypeFilter((prev) => (prev === kind ? null : kind));

    return (
        <>
            <Show when={props.availableArchitectures.length > 1}>
                <div class="tab-bar mb-md">
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
            <div
                class="mb-md"
                style={{
                    display: "flex",
                    "align-items": "center",
                    gap: "8px",
                    "flex-wrap": "wrap",
                }}
            >
                <label
                    style={{
                        display: "flex",
                        "align-items": "center",
                        gap: "6px",
                        cursor: "pointer",
                        "font-size": "0.875rem",
                    }}
                >
                    <input
                        type="checkbox"
                        checked={packagesOnly()}
                        onChange={(e) => setPackagesOnly(e.target.checked)}
                    />
                    Packages only
                </label>
                <input
                    type="text"
                    placeholder="Filter by package…"
                    value={nameFilter()}
                    onInput={(e) => setNameFilter(e.currentTarget.value)}
                    style={{
                        flex: "1",
                        "min-width": "160px",
                        "font-size": "0.875rem",
                    }}
                />
            </div>
            <For each={props.entries}>
                {(entry) => (
                    <DiffEntry
                        entry={entry}
                        packagesOnly={packagesOnly()}
                        typeFilter={typeFilter()}
                        nameFilter={nameFilter()}
                        onTypeFilterToggle={toggleTypeFilter}
                    />
                )}
            </For>
        </>
    );
}
