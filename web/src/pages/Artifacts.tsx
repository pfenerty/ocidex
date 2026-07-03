import { createMemo, createSignal, For, Show } from "solid-js";
import { A } from "@solidjs/router";
import { useArtifactsInfinite } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import LoadMore from "~/components/LoadMore";
import { artifactDisplayName, plural } from "~/utils/format";
import { SigningBadge, TypeBadge } from "~/components/ui";
import type { ArtifactSummary } from "~/api/client";

function extractNamespace(name: string): string {
    const parts = name.split("/");
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0];
}

export default function Artifacts() {
    const [nameFilter, setNameFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("");
    const [showAll, setShowAll] = createSignal(false);

    const query = useArtifactsInfinite(() => ({
        name: nameFilter(),
        type: typeFilter(),
        limit: 50,
        sufficient: showAll() ? false : true,
    }));

    const artifacts = () => query.data?.pages.flatMap((p) => p.data ?? []) ?? [];

    const grouped = createMemo(() => {
        const map = new Map<string, ArtifactSummary[]>();
        for (const a of artifacts()) {
            const ns = extractNamespace(a.name);
            const bucket = map.get(ns);
            if (bucket) {
                bucket.push(a);
            } else {
                map.set(ns, [a]);
            }
        }
        return [...map.entries()];
    });

    const handleSearch = (e: Event) => {
        e.preventDefault();
    };

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Artifacts</h2>
                        <p>
                            Software artifacts (container images, libraries,
                            applications) tracked by OCIDex
                        </p>
                    </div>
                </div>
            </div>

            <form class="search-bar mb-4" onSubmit={handleSearch}>
                <input
                    type="text"
                    placeholder="Filter by name…"
                    value={nameFilter()}
                    onInput={(e) => setNameFilter(e.currentTarget.value)}
                />
                <input
                    type="text"
                    placeholder="Filter by type…"
                    value={typeFilter()}
                    onInput={(e) => setTypeFilter(e.currentTarget.value)}
                />
                <button type="submit" class="btn-primary">
                    Search
                </button>
            </form>

            <div class="mb-4" style={{ display: "flex", "align-items": "center", gap: "0.5rem" }}>
                <label style={{ display: "flex", "align-items": "center", gap: "0.5rem", cursor: "pointer" }}>
                    <input
                        type="checkbox"
                        checked={showAll()}
                        onChange={(e) => setShowAll(e.currentTarget.checked)}
                    />
                    Show insufficiently enriched artifacts
                </label>
            </div>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    <Show
                        when={artifacts().length > 0}
                        fallback={
                            <EmptyState
                                title="No artifacts found"
                                message="Ingest an SBOM to get started."
                            />
                        }
                    >
                        <div style={{ display: "flex", "flex-direction": "column", gap: "1rem" }}>
                            <For each={grouped()}>
                                {([ns, items]) => (
                                    <details class="card" open>
                                        <summary class="card-summary">
                                            <span style={{ "font-weight": "600", "margin-right": "0.5rem" }}>{ns}</span>
                                            <span class="badge">{items.length}</span>
                                        </summary>
                                        <div class="table-wrapper">
                                            <table>
                                                <thead>
                                                    <tr>
                                                        <th>Artifact</th>
                                                        <th>Type</th>
                                                        <th>Signing</th>
                                                        <th>SBOMs</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <For each={items}>
                                                        {(artifact) => (
                                                            <tr>
                                                                <td>
                                                                    <A href={`/artifacts/${artifact.id}`}>
                                                                        {artifactDisplayName(artifact)}
                                                                    </A>
                                                                </td>
                                                                <td>
                                                                    <TypeBadge type={artifact.type} />
                                                                </td>
                                                                <td>
                                                                    <SigningBadge status={artifact.signingStatus} />
                                                                </td>
                                                                <td>
                                                                    {plural(artifact.sbomCount, "SBOM")}
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </For>
                                                </tbody>
                                            </table>
                                        </div>
                                    </details>
                                )}
                            </For>
                            <LoadMore
                                hasMore={query.hasNextPage}
                                loading={query.isFetchingNextPage}
                                onClick={() => void query.fetchNextPage()}
                            />
                        </div>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
