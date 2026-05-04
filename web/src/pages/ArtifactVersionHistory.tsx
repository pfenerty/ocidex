import { For, Show, createSignal } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useArtifact, useArtifactSBOMs, useDiff, useSBOMDependencies } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import DiffEntry from "~/components/DiffEntry";
import DiffTreeView from "~/components/DiffTreeView";

export default function ArtifactVersionHistory() {
    const params = useParams<{ id: string; version: string }>();
    const version = () => decodeURIComponent(params.version);

    const artifactQuery = useArtifact(() => params.id);

    const sbomsQuery = useArtifactSBOMs(
        () => params.id,
        () => ({ image_version: version(), limit: 200 }),
    );

    const [selectedArch, setSelectedArch] = createSignal<string | undefined>("amd64");
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");

    const allArchs = () => {
        const sboms = sbomsQuery.data?.data ?? [];
        const archs = new Set<string>();
        for (const s of sboms) {
            if (s.architecture !== undefined) archs.add(s.architecture);
        }
        return [...archs].sort();
    };

    // API returns created_at DESC — filter to selected arch (or all), keep order.
    const builds = () => {
        const sboms = sbomsQuery.data?.data ?? [];
        const arch = selectedArch();
        return arch !== undefined ? sboms.filter((s) => s.architecture === arch) : sboms;
    };

    // Consecutive pairs: newer = builds[i], older = builds[i+1]
    const pairs = () => {
        const b = builds();
        return b.slice(0, -1).map((newer, i) => ({ newer, older: b[i + 1] }));
    };

    return (
        <>
            <div class="breadcrumb">
                <A href="/artifacts">Artifacts</A>
                <span class="separator">/</span>
                <A href={`/artifacts/${params.id}`}>
                    {artifactQuery.data?.name ?? params.id}
                </A>
                <span class="separator">/</span>
                <span>{version()}</span>
            </div>

            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>{version()}</h2>
                        <p class="text-muted">Build changelog</p>
                    </div>
                    <div class="btn-group">
                        <button
                            class={`btn btn-sm${viewMode() === "tree" ? " active" : ""}`}
                            onClick={() => setViewMode("tree")}
                        >
                            Tree
                        </button>
                        <button
                            class={`btn btn-sm${viewMode() === "list" ? " active" : ""}`}
                            onClick={() => setViewMode("list")}
                        >
                            List
                        </button>
                    </div>
                </div>
            </div>

            <Show when={!sbomsQuery.isLoading} fallback={<Loading />}>
                <Show
                    when={!sbomsQuery.isError}
                    fallback={<ErrorBox error={sbomsQuery.error} />}
                >
                    <Show when={allArchs().length > 1}>
                        <div class="tab-bar mb-md">
                            <For each={allArchs()}>
                                {(arch) => (
                                    <button
                                        class={selectedArch() === arch ? "active" : ""}
                                        onClick={() =>
                                            setSelectedArch((a) =>
                                                a === arch ? undefined : arch,
                                            )
                                        }
                                    >
                                        {arch}
                                    </button>
                                )}
                            </For>
                        </div>
                    </Show>

                    <Show
                        when={builds().length > 0}
                        fallback={
                            <EmptyState
                                title="No builds found"
                                message="No SBOMs found for this version."
                            />
                        }
                    >
                        <Show
                            when={pairs().length > 0}
                            fallback={
                                <EmptyState
                                    title="Only one build"
                                    message="No previous build to compare against for this version."
                                />
                            }
                        >
                            <For each={pairs()}>
                                {(pair) => (
                                    <BuildDiffEntry
                                        fromId={pair.older.id}
                                        toId={pair.newer.id}
                                        viewMode={viewMode()}
                                    />
                                )}
                            </For>
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}

function BuildDiffEntry(props: {
    fromId: string;
    toId: string;
    viewMode: "tree" | "list";
}) {
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter] = createSignal("");
    const diff = useDiff(() => ({ from: props.fromId, to: props.toId }));
    const depsQuery = useSBOMDependencies(
        () => props.toId,
        { enabled: () => props.viewMode === "tree" },
    );

    return (
        <>
            <Show when={diff.isLoading || (props.viewMode === "tree" && depsQuery.isLoading)}>
                <Loading />
            </Show>
            <Show when={diff.isError}>
                <ErrorBox error={diff.error} />
            </Show>
            <Show when={depsQuery.isError}>
                <ErrorBox error={depsQuery.error} />
            </Show>
            <Show when={diff.data} keyed>
                {(entry) => (
                    <Show
                        when={props.viewMode === "tree" ? depsQuery.data : undefined}
                        keyed
                        fallback={
                            <DiffEntry
                                entry={entry}
                                packagesOnly={true}
                                typeFilter={typeFilter()}
                                nameFilter={nameFilter()}
                                onTypeFilterToggle={(k) =>
                                    setTypeFilter((f) => (f === k ? null : k))
                                }
                            />
                        }
                    >
                        {(graph) => <DiffTreeView entry={entry} graph={graph} />}
                    </Show>
                )}
            </Show>
        </>
    );
}
