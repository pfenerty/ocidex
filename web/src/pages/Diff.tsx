import { createSignal, Show, For } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import { useArtifacts, useArtifactSBOMs } from "~/api/queries";
import { EmptyState } from "~/components/Feedback";
import { DiffPairView, ViewToggle } from "~/components/DiffPairView";
import { sbomLabel } from "~/utils/format";

export default function Diff() {
    const [searchParams, setSearchParams] = useSearchParams<{
        from?: string;
        to?: string;
    }>();

    const [fromArtifactId, setFromArtifactId] = createSignal("");
    const [toArtifactId, setToArtifactId] = createSignal("");
    const [fromSbomId, setFromSbomId] = createSignal(searchParams.from ?? "");
    const [toSbomId, setToSbomId] = createSignal(searchParams.to ?? "");
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");

    const artifactsQuery = useArtifacts(() => ({ limit: 200 }));

    const fromSbomsQuery = useArtifactSBOMs(
        () => fromArtifactId(),
        () => ({ limit: 200 }),
        { enabled: () => fromArtifactId() !== "" },
    );

    const toSbomsQuery = useArtifactSBOMs(
        () => toArtifactId(),
        () => ({ limit: 200 }),
        { enabled: () => toArtifactId() !== "" },
    );

    function handleCompare() {
        if (fromSbomId() !== "" && toSbomId() !== "") {
            setSearchParams({ from: fromSbomId(), to: toSbomId() });
        }
    }

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Compare SBOMs</h2>
                        <p>Select two SBOMs to see what changed between them.</p>
                    </div>
                    <Show when={searchParams.from !== undefined && searchParams.to !== undefined}>
                        <ViewToggle mode={viewMode()} onChange={setViewMode} />
                    </Show>
                </div>
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

            <Show
                when={searchParams.from !== undefined && searchParams.to !== undefined}
                fallback={
                    <EmptyState
                        title="Select two SBOMs"
                        message="Choose a 'from' and 'to' SBOM above and click Compare."
                    />
                }
            >
                <DiffPairView
                    fromId={searchParams.from ?? ""}
                    toId={searchParams.to ?? ""}
                    viewMode={viewMode()}
                />
            </Show>
        </>
    );
}
