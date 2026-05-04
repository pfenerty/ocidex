import { createSignal, Show } from "solid-js";
import { useDiffTree } from "~/api/queries";
import { Loading, ErrorBox } from "~/components/Feedback";
import DiffEntry from "~/components/DiffEntry";
import { DiffTreeView } from "~/components/DiffTreeView";
import type { ChangelogEntryData } from "~/utils/diff";
import type { DiffTree } from "~/api/client";

// Extract the ChangelogEntry-compatible subset from a DiffTree response.
function asEntry(tree: DiffTree): ChangelogEntryData {
    return {
        from: tree.from,
        to: tree.to,
        summary: tree.summary,
        changes: tree.changes ?? [],
    };
}

// Renders a single from→to SBOM comparison as either a dependency tree
// or a flat list. Always fetches diff-tree (backend handles all filtering);
// list mode uses the same response data without a second request.
export function DiffPairView(props: {
    fromId: string;
    toId: string;
    viewMode: "tree" | "list";
}) {
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter] = createSignal("");

    const query = useDiffTree(() => ({ from: props.fromId, to: props.toId }));

    return (
        <>
            <Show when={query.isLoading}><Loading /></Show>
            <Show when={query.isError}><ErrorBox error={query.error} /></Show>
            <Show when={query.data} keyed>
                {(tree) => (
                    <Show
                        when={props.viewMode === "tree"}
                        fallback={
                            <DiffEntry
                                entry={asEntry(tree)}
                                packagesOnly={false}
                                typeFilter={typeFilter()}
                                nameFilter={nameFilter()}
                                onTypeFilterToggle={(k) =>
                                    setTypeFilter((f) => (f === k ? null : k))
                                }
                            />
                        }
                    >
                        <DiffTreeView tree={tree} />
                    </Show>
                )}
            </Show>
        </>
    );
}

// ViewToggle renders the Tree / List btn-group used on every diff page.
export function ViewToggle(props: {
    mode: "tree" | "list";
    onChange: (mode: "tree" | "list") => void;
}) {
    return (
        <div class="btn-group">
            <button
                class={`btn btn-sm${props.mode === "tree" ? " active" : ""}`}
                onClick={() => props.onChange("tree")}
            >
                Tree
            </button>
            <button
                class={`btn btn-sm${props.mode === "list" ? " active" : ""}`}
                onClick={() => props.onChange("list")}
            >
                List
            </button>
        </div>
    );
}
