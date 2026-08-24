import { For, Show, createSignal } from "solid-js";
import { useParams } from "@solidjs/router";
import { useArtifact, useArtifactSBOMs } from "~/api/queries";
import { EmptyState } from "~/components/Feedback";
import { SkeletonText } from "~/components/Skeleton";
import { DiffPairView, ViewToggle } from "~/components/DiffPairView";
import { Breadcrumb, PageHeader, QueryBoundary, TabBar } from "~/components/ui";

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

    const builds = () => {
        const sboms = sbomsQuery.data?.data ?? [];
        const arch = selectedArch();
        return arch !== undefined ? sboms.filter((s) => s.architecture === arch) : sboms;
    };

    const pairs = () => {
        const b = builds();
        return b.slice(0, -1).map((newer, i) => ({ newer, older: b[i + 1] }));
    };

    return (
        <>
            <PageHeader
                breadcrumb={
                    <Breadcrumb
                        items={[
                            { label: "Artifacts", href: "/artifacts" },
                            {
                                label: artifactQuery.data?.name ?? params.id,
                                href: `/artifacts/${params.id}`,
                            },
                            { label: version(), mono: true },
                        ]}
                    />
                }
                title={version()}
                subtitle="Build changelog"
                actions={<ViewToggle mode={viewMode()} onChange={setViewMode} />}
            />

            <QueryBoundary query={sbomsQuery} loading={<SkeletonText lines={8} />}>
                {() => (
                    <>
                        <Show when={allArchs().length > 1}>
                            <TabBar
                                variant="filter"
                                label="Architecture"
                                tabs={allArchs().map((a) => ({ id: a, label: a }))}
                                active={selectedArch() ?? ""}
                                onSelect={(arch) =>
                                    setSelectedArch((a) => (a === arch ? undefined : arch))
                                }
                                class="mb-4"
                            />
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
                                        <DiffPairView
                                            fromId={pair.older.id}
                                            toId={pair.newer.id}
                                            viewMode={viewMode()}
                                        />
                                    )}
                                </For>
                            </Show>
                        </Show>
                    </>
                )}
            </QueryBoundary>
        </>
    );
}
