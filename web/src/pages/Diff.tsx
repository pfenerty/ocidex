import "~/components/DetailSection.css";
import { createSignal, createMemo, Show, For } from "solid-js";
import { createLocalStorageSignal } from "~/utils/prefs";
import "./Diff.css";
import { useSearchParams } from "@solidjs/router";
import { useArtifacts, useArtifactSBOMs } from "~/api/queries";
import { EmptyState } from "~/components/Feedback";
import { DiffPairView, ViewToggle } from "~/components/DiffPairView";
import { sbomPickerLabel } from "~/utils/format";

export default function Diff() {
    const [searchParams, setSearchParams] = useSearchParams<{
        from?: string;
        to?: string;
    }>();

    const [fromArtifactId, setFromArtifactId] = createSignal("");
    const [toArtifactId, setToArtifactId] = createSignal("");
    const [fromSbomId, setFromSbomId] = createSignal(searchParams.from ?? "");
    const [toSbomId, setToSbomId] = createSignal(searchParams.to ?? "");
    const [viewMode, setViewMode] = createLocalStorageSignal<"tree" | "list">("ocidex.diff.viewMode", "tree");
    const [showAllArchs, setShowAllArchs] = createSignal(false);

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

    // Architecture of the currently-selected From SBOM. Drives the To-side filter
    // so users don't accidentally pick a cross-arch comparison (which produces a
    // wall of phantom remove+add per ADR-0019 arch identity).
    const fromSbomArch = createMemo(() => {
        const sboms = fromSbomsQuery.data?.data ?? [];
        const sel = sboms.find((s) => s.id === fromSbomId());
        return sel?.architecture;
    });

    const toSbomOptions = createMemo(() => {
        const sboms = toSbomsQuery.data?.data ?? [];
        const arch = fromSbomArch();
        if (showAllArchs() || arch === undefined || arch === "") return sboms;
        return sboms.filter((s) => s.architecture === arch);
    });

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

            <div class="card mb-6">
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
                                    <option value={s.id}>{sbomPickerLabel(s)}</option>
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
                            <For each={toSbomOptions()}>
                                {(s) => (
                                    <option value={s.id}>{sbomPickerLabel(s)}</option>
                                )}
                            </For>
                        </select>
                    </div>
                </div>

                <Show when={fromSbomArch() !== undefined && fromSbomArch() !== ""}>
                    <label
                        style={{ display: "flex", gap: "0.4rem", "align-items": "center", "font-size": "0.85rem", cursor: "pointer", "margin-top": "0.75rem" }}
                    >
                        <input
                            type="checkbox"
                            checked={showAllArchs()}
                            onChange={(e) => setShowAllArchs(e.currentTarget.checked)}
                        />
                        Show all architectures (default: match {fromSbomArch()})
                    </label>
                </Show>

                <div class="mt-4">
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
