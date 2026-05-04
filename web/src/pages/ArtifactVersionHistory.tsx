import { For, Show, createSignal } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useArtifact, useArtifactSBOMs, useDiff } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import DiffEntry from "~/components/DiffEntry";

export default function ArtifactVersionHistory() {
    const params = useParams<{ id: string; version: string }>();
    const version = () => decodeURIComponent(params.version);

    const artifactQuery = useArtifact(() => params.id);

    const sbomsQuery = useArtifactSBOMs(
        () => params.id,
        () => ({ image_version: version(), limit: 200 }),
    );

    const [selectedArch, setSelectedArch] = createSignal<string | undefined>("amd64");
    const [showPlanFiles, setShowPlanFiles] = createSignal(false);

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
                            <div class="mb-md" style={{ display: "flex", "align-items": "center", gap: "8px" }}>
                                <label style={{ display: "flex", "align-items": "center", gap: "6px", cursor: "pointer", "font-size": "0.875rem" }}>
                                    <input
                                        type="checkbox"
                                        checked={showPlanFiles()}
                                        onChange={(e) => setShowPlanFiles(e.target.checked)}
                                    />
                                    Show plan files
                                </label>
                            </div>
                            <For each={pairs()}>
                                {(pair) => (
                                    <BuildDiffEntry
                                        fromId={pair.older.id}
                                        toId={pair.newer.id}
                                        showPlanFiles={showPlanFiles()}
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

function BuildDiffEntry(props: { fromId: string; toId: string; showPlanFiles: boolean }) {
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter] = createSignal("");
    const diff = useDiff(() => ({ from: props.fromId, to: props.toId }));

    return (
        <>
            <Show when={diff.isLoading}>
                <Loading />
            </Show>
            <Show when={diff.isError}>
                <ErrorBox error={diff.error} />
            </Show>
            <Show when={diff.data}>
                {(data) => (
                    <DiffEntry
                        entry={data()}
                        packagesOnly={false}
                        showPlanFiles={props.showPlanFiles}
                        typeFilter={typeFilter()}
                        nameFilter={nameFilter()}
                        onTypeFilterToggle={(k) =>
                            setTypeFilter((f) => (f === k ? null : k))
                        }
                    />
                )}
            </Show>
        </>
    );
}
