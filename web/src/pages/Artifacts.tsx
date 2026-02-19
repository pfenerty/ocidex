import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { useArtifacts } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { artifactDisplayName, plural } from "~/utils/format";

export default function Artifacts() {
    const [offset, setOffset] = createSignal(0);
    const [nameFilter, setNameFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("");
    const limit = 50;

    const query = useArtifacts(() => ({
        name: nameFilter(),
        type: typeFilter(),
        limit,
        offset: offset(),
    }));

    const handleSearch = (e: Event) => {
        e.preventDefault();
        setOffset(0);
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

            <form class="search-bar mb-md" onSubmit={handleSearch}>
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

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    <Show
                        when={query.data && query.data.data.length > 0}
                        fallback={
                            <EmptyState
                                title="No artifacts found"
                                message="Ingest an SBOM to get started."
                            />
                        }
                    >
                        <div class="card">
                            <div class="table-wrapper">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Artifact</th>
                                            <th>Type</th>
                                            <th>SBOMs</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <For each={query.data!.data}>
                                            {(artifact) => (
                                                <tr>
                                                    <td>
                                                        <A
                                                            href={`/artifacts/${artifact.id}`}
                                                        >
                                                            {artifactDisplayName(
                                                                artifact,
                                                            )}
                                                        </A>
                                                    </td>
                                                    <td>
                                                        <span class="badge">
                                                            {artifact.type}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        {plural(
                                                            artifact.sbomCount,
                                                            "SBOM",
                                                        )}
                                                    </td>
                                                </tr>
                                            )}
                                        </For>
                                    </tbody>
                                </table>
                            </div>
                            <Pagination
                                pagination={query.data!.pagination}
                                onPageChange={setOffset}
                            />
                        </div>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
