import "~/components/DetailSection.css";
import { createSignal, createMemo, Show } from "solid-js";
import { createLocalStorageSignal } from "~/utils/prefs";
import "./Diff.css";
import { useSearchParams } from "@solidjs/router";
import { useArtifacts, useArtifactSBOMs } from "~/api/queries";
import { EmptyState } from "~/components/Feedback";
import { DiffPairView, ViewToggle } from "~/components/DiffPairView";
import { sbomPickerLabel } from "~/utils/format";
import type { ArtifactSummary, SBOMSummary } from "~/api/client";
import { Button, Card, Combobox, PageHeader } from "~/components/ui";

/** "group/name" — the identity a reader types to find an artifact. */
function artifactLabel(a: ArtifactSummary): string {
    return a.group !== undefined ? `${a.group}/${a.name}` : a.name;
}

/**
 * The searchable second line of an SBOM option. Arch and flavor are already in
 * `sbomPickerLabel`, but the digest is not — and a digest prefix is exactly
 * what someone arrives with when they were sent a specific build to compare.
 */
function sbomSub(s: SBOMSummary): string | undefined {
    return s.digest;
}

/** builtAt is when an SBOM's subject was built, or ingested if that is unknown. */
function builtAt(s: SBOMSummary): string {
    return s.buildDate ?? s.createdAt;
}

/**
 * byBuildNewestFirst orders picker options by build time. Ingest order put a
 * 10:36 build above a 13:07 one because a scan ingested both at 13:18
 * (ocidex-nps9.20).
 */
function byBuildNewestFirst(sboms: SBOMSummary[]): SBOMSummary[] {
    return [...sboms].sort((a, b) => builtAt(b).localeCompare(builtAt(a)));
}

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

    const fromSbomOptions = createMemo(() => byBuildNewestFirst(fromSbomsQuery.data?.data ?? []));

    const toSbomOptions = createMemo(() => {
        const sboms = byBuildNewestFirst(toSbomsQuery.data?.data ?? []);
        const arch = fromSbomArch();
        if (showAllArchs() || arch === undefined || arch === "") return sboms;
        return sboms.filter((s) => s.architecture === arch);
    });

    // A diff reads FROM → TO, so picking a newer FROM inverts every change:
    // upgrades read as downgrades. Said, with a one-click fix, rather than
    // left for the result to look wrong.
    const reversed = createMemo(() => {
        const from = fromSbomsQuery.data?.data.find((s) => s.id === fromSbomId());
        const to = toSbomsQuery.data?.data.find((s) => s.id === toSbomId());
        return from !== undefined && to !== undefined && builtAt(from) > builtAt(to);
    });

    function swap() {
        const [fa, fs, ta, ts] = [fromArtifactId(), fromSbomId(), toArtifactId(), toSbomId()];
        setFromArtifactId(ta);
        setFromSbomId(ts);
        setToArtifactId(fa);
        setToSbomId(fs);
    }

    function handleCompare() {
        if (fromSbomId() !== "" && toSbomId() !== "") {
            setSearchParams({ from: fromSbomId(), to: toSbomId() });
        }
    }

    return (
        <>
            <PageHeader
                title="Compare SBOMs"
                subtitle="Select two SBOMs to see what changed between them."
                actions={
                    <Show when={searchParams.from !== undefined && searchParams.to !== undefined}>
                        <ViewToggle mode={viewMode()} onChange={setViewMode} />
                    </Show>
                }
            />

            <Card class="mb-6">
                <div class="diff-picker">
                    {/* FROM side */}
                    <div class="diff-picker-side">
                        <label class="detail-label">From</label>
                        <Combobox
                            label="From artifact"
                            placeholder="Search artifacts..."
                            items={artifactsQuery.data?.data ?? []}
                            value={fromArtifactId()}
                            onSelect={(id) => {
                                setFromArtifactId(id);
                                setFromSbomId("");
                            }}
                            itemId={(a) => a.id}
                            itemLabel={artifactLabel}
                            itemSub={(a) => a.type}
                            emptyMessage="No artifacts match"
                        />
                        <Combobox
                            label="From SBOM"
                            placeholder="Search SBOMs..."
                            items={fromSbomOptions()}
                            value={fromSbomId()}
                            onSelect={setFromSbomId}
                            itemId={(s) => s.id}
                            itemLabel={sbomPickerLabel}
                            itemSub={sbomSub}
                            disabled={fromArtifactId() === ""}
                            emptyMessage={fromSbomsQuery.isLoading ? "Loading SBOMs…" : "No SBOMs match"}
                        />
                    </div>

                    {/* TO side */}
                    <div class="diff-picker-side">
                        <label class="detail-label">To</label>
                        <Combobox
                            label="To artifact"
                            placeholder="Search artifacts..."
                            items={artifactsQuery.data?.data ?? []}
                            value={toArtifactId()}
                            onSelect={(id) => {
                                setToArtifactId(id);
                                setToSbomId("");
                            }}
                            itemId={(a) => a.id}
                            itemLabel={artifactLabel}
                            itemSub={(a) => a.type}
                            emptyMessage="No artifacts match"
                        />
                        <Combobox
                            label="To SBOM"
                            placeholder="Search SBOMs..."
                            items={toSbomOptions()}
                            value={toSbomId()}
                            onSelect={setToSbomId}
                            itemId={(s) => s.id}
                            itemLabel={sbomPickerLabel}
                            itemSub={sbomSub}
                            disabled={toArtifactId() === ""}
                            emptyMessage={toSbomsQuery.isLoading ? "Loading SBOMs…" : "No SBOMs match"}
                        />
                    </div>
                </div>

                <Show when={fromSbomArch() !== undefined && fromSbomArch() !== ""}>
                    <label
                        class="mt-3 flex cursor-pointer items-center gap-[0.4rem] text-[0.85rem]"
                    >
                        <input
                            type="checkbox"
                            checked={showAllArchs()}
                            onChange={(e) => setShowAllArchs(e.currentTarget.checked)}
                        />
                        Show all architectures (default: match {fromSbomArch()})
                    </label>
                </Show>

                <Show when={reversed()}>
                    <p class="mt-3 text-sm">
                        <span class="text-muted">From was built after To, so changes will read backwards.</span>{" "}
                        <button type="button" class="link-button" onClick={swap}>
                            Swap
                        </button>
                    </p>
                </Show>

                <div class="mt-4">
                    <Button
                        variant="primary"
                        disabled={fromSbomId() === "" || toSbomId() === ""}
                        onClick={handleCompare}
                    >
                        Compare
                    </Button>
                </div>
            </Card>

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
