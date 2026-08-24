import { createSignal, Show } from "solid-js";
import { useDiffTree } from "~/api/queries";
import { SkeletonText } from "~/components/Skeleton";
import DiffEntry from "~/components/DiffEntry";
import { DiffTreeView } from "~/components/DiffTreeView";
import type { ChangelogEntryData } from "~/utils/diff";
import type { DiffTree } from "~/api/client";
import { Button, ButtonGroup, QueryBoundary } from "~/components/ui";

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
    hideHeader?: boolean;
}) {
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter] = createSignal("");

    const query = useDiffTree(() => ({ from: props.fromId, to: props.toId }));

    return (
        <>
            {/* Three sibling <Show>s used to be able to paint at once: an error
                arriving over stale data rendered the ErrorBox *and* the tree
                below it. The boundary makes the states exclusive. */}
            <QueryBoundary query={query} loading={<SkeletonText lines={8} />}>
                {(data) => {
                    const tree = data();
                    const hasTree = () =>
                        (tree.roots?.length ?? 0) > 0 || tree.edges.length > 0;
                    const effectiveMode = () => (hasTree() ? props.viewMode : "list");
                    const fromArch = tree.from.architecture;
                    const toArch = tree.to.architecture;
                    const crossArch = fromArch !== undefined && fromArch !== "" &&
                        toArch !== undefined && toArch !== "" &&
                        fromArch !== toArch;
                    return (
                    <>
                    <Show when={crossArch}>
                        <div class="alert alert-warning mb-4">
                            Comparing across architectures ({fromArch} → {toArch}).
                            Most package identities include the architecture, so changes here
                            will appear as removed+added rather than upgraded. Pick same-arch
                            SBOMs for a cleaner diff.
                        </div>
                    </Show>
                    <Show
                        when={effectiveMode() === "tree"}
                        fallback={
                            <DiffEntry
                                entry={asEntry(tree)}
                                packagesOnly={false}
                                typeFilter={typeFilter()}
                                nameFilter={nameFilter()}
                                onTypeFilterToggle={(k) =>
                                    setTypeFilter((f) => (f === k ? null : k))
                                }
                                hideHeader={props.hideHeader}
                            />
                        }
                    >
                        <DiffTreeView tree={tree} hideHeader={props.hideHeader} />
                    </Show>
                    </>
                    );
                }}
            </QueryBoundary>
        </>
    );
}

// ViewToggle renders the Tree / List btn-group used on every diff page.
export function ViewToggle(props: {
    mode: "tree" | "list";
    onChange: (mode: "tree" | "list") => void;
}) {
    return (
        <ButtonGroup>
            <Button size="sm" active={props.mode === "tree"} onClick={() => props.onChange("tree")}>
                Tree
            </Button>
            <Button size="sm" active={props.mode === "list"} onClick={() => props.onChange("list")}>
                List
            </Button>
        </ButtonGroup>
    );
}
