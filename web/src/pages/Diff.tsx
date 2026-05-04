import { createSignal, Show, For } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import { useArtifacts, useArtifactSBOMs } from "~/api/queries";
import { useDiff } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import DiffEntry from "~/components/DiffEntry";
import { sbomLabel } from "~/utils/format";

export default function Diff() {
    const [searchParams, setSearchParams] = useSearchParams<{
        from?: string;
        to?: string;
    }>();

    // Artifact selection for picker
    const [fromArtifactId, setFromArtifactId] = createSignal("");
    const [toArtifactId, setToArtifactId] = createSignal("");
    const [fromSbomId, setFromSbomId] = createSignal(searchParams.from ?? "");
    const [toSbomId, setToSbomId] = createSignal(searchParams.to ?? "");

    // Load all artifacts for the pickers
    const artifactsQuery = useArtifacts(() => ({ limit: 200 }));

    // Load SBOMs for the selected "from" artifact
    const fromSbomsQuery = useArtifactSBOMs(
        () => fromArtifactId(),
        () => ({ limit: 200 }),
        { enabled: () => fromArtifactId() !== "" },
    );

    // Load SBOMs for the selected "to" artifact
    const toSbomsQuery = useArtifactSBOMs(
        () => toArtifactId(),
        () => ({ limit: 200 }),
        { enabled: () => toArtifactId() !== "" },
    );

    // Run the diff when both SBOM IDs are set via URL params
    const diffQuery = useDiff(() => ({
        from: searchParams.from,
        to: searchParams.to,
    }));

    function handleCompare() {
        if (fromSbomId() !== "" && toSbomId() !== "") {
            setSearchParams({ from: fromSbomId(), to: toSbomId() });
        }
    }

    const [packagesOnly, setPackagesOnly] = createSignal(true);
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter, setNameFilter] = createSignal("");
    const toggleTypeFilter = (kind: string) =>
        setTypeFilter(prev => prev === kind ? null : kind);

    return (
        <>
            <div class="page-header">
                <h2>Compare SBOMs</h2>
                <p>Select two SBOMs to see what changed between them.</p>
            </div>

            <div class="card mb-lg">
                <div class="diff-picker">
                    {/* FROM side */}
                    <div class="diff-picker-side">
                        <label class="detail-label">From</label>
                        <select
                            value={fromArtifactId()}
                            onChange={(e) => {
                                setFromArtifactId(e.target.value);
                                setFromSbomId("");
                            }}
                        >
                            <option value="">Select artifact...</option>
                            <For each={artifactsQuery.data?.data}>
                                {(a) => (
                                    <option value={a.id}>
                                        {a.group !== undefined ? `${a.group}/` : ""}
                                        {a.name} ({a.type})
                                    </option>
                                )}
                            </For>
                        </select>
                        <select
                            value={fromSbomId()}
                            onChange={(e) => setFromSbomId(e.target.value)}
                            disabled={fromArtifactId() === ""}
                        >
                            <option value="">Select SBOM...</option>
                            <For each={fromSbomsQuery.data?.data}>
                                {(s) => (
                                    <option value={s.id}>{sbomLabel(s)}</option>
                                )}
                            </For>
                        </select>
                    </div>

                    {/* TO side */}
                    <div class="diff-picker-side">
                        <label class="detail-label">To</label>
                        <select
                            value={toArtifactId()}
                            onChange={(e) => {
                                setToArtifactId(e.target.value);
                                setToSbomId("");
                            }}
                        >
                            <option value="">Select artifact...</option>
                            <For each={artifactsQuery.data?.data}>
                                {(a) => (
                                    <option value={a.id}>
                                        {a.group !== undefined ? `${a.group}/` : ""}
                                        {a.name} ({a.type})
                                    </option>
                                )}
                            </For>
                        </select>
                        <select
                            value={toSbomId()}
                            onChange={(e) => setToSbomId(e.target.value)}
                            disabled={toArtifactId() === ""}
                        >
                            <option value="">Select SBOM...</option>
                            <For each={toSbomsQuery.data?.data}>
                                {(s) => (
                                    <option value={s.id}>{sbomLabel(s)}</option>
                                )}
                            </For>
                        </select>
                    </div>
                </div>

                <div class="mt-md">
                    <button
                        class="btn-primary"
                        disabled={fromSbomId() === "" || toSbomId() === ""}
                        onClick={handleCompare}
                    >
                        Compare
                    </button>
                </div>
            </div>

            {/* Diff results */}
            <Show when={searchParams.from !== undefined && searchParams.to !== undefined}>
                <Show when={!diffQuery.isLoading} fallback={<Loading />}>
                    <Show
                        when={!diffQuery.isError}
                        fallback={<ErrorBox error={diffQuery.error} />}
                    >
                        <Show
                            when={diffQuery.data}
                            fallback={
                                <EmptyState
                                    title="No results"
                                    message="Could not compute diff."
                                />
                            }
                        >
                            {(entry) => (
                                <>
                                    <div class="mb-md" style={{ display: "flex", "align-items": "center", gap: "8px", "flex-wrap": "wrap" }}>
                                        <label style={{ display: "flex", "align-items": "center", gap: "6px", cursor: "pointer", "font-size": "0.875rem" }}>
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
                                            style={{ flex: "1", "min-width": "160px", "font-size": "0.875rem" }}
                                        />
                                    </div>
                                    <DiffEntry
                                        entry={entry()}
                                        packagesOnly={packagesOnly()}
                                        typeFilter={typeFilter()}
                                        nameFilter={nameFilter()}
                                        onTypeFilterToggle={toggleTypeFilter}
                                    />
                                </>
                            )}
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
