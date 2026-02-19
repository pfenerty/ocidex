import { createSignal, Show, For } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useArtifacts, useArtifactSBOMs } from "~/api/queries";
import { useDiff } from "~/api/queries";
import type { SBOMSummary } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import { purlDisplayName } from "~/utils/purl";

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
        { enabled: () => !!fromArtifactId() },
    );

    // Load SBOMs for the selected "to" artifact
    const toSbomsQuery = useArtifactSBOMs(
        () => toArtifactId(),
        () => ({ limit: 200 }),
        { enabled: () => !!toArtifactId() },
    );

    // Run the diff when both SBOM IDs are set via URL params
    const diffQuery = useDiff(() => ({
        from: searchParams.from,
        to: searchParams.to,
    }));

    function handleCompare() {
        if (fromSbomId() && toSbomId()) {
            setSearchParams({ from: fromSbomId(), to: toSbomId() });
        }
    }

    function sbomLabel(sbom: SBOMSummary): string {
        const version = sbom.subjectVersion ?? "";
        const date = new Date(sbom.createdAt).toLocaleDateString();
        const idShort = sbom.id.slice(0, 8);
        return version
            ? `${version} (${date}) ${idShort}`
            : `${idShort} (${date})`;
    }

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
                                        {a.group ? `${a.group}/` : ""}
                                        {a.name} ({a.type})
                                    </option>
                                )}
                            </For>
                        </select>
                        <select
                            value={fromSbomId()}
                            onChange={(e) => setFromSbomId(e.target.value)}
                            disabled={!fromArtifactId()}
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
                                        {a.group ? `${a.group}/` : ""}
                                        {a.name} ({a.type})
                                    </option>
                                )}
                            </For>
                        </select>
                        <select
                            value={toSbomId()}
                            onChange={(e) => setToSbomId(e.target.value)}
                            disabled={!toArtifactId()}
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
                        disabled={!fromSbomId() || !toSbomId()}
                        onClick={handleCompare}
                    >
                        Compare
                    </button>
                </div>
            </div>

            {/* Diff results */}
            <Show when={searchParams.from && searchParams.to}>
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
                                    <div class="changelog-entry">
                                        <div class="changelog-entry-header">
                                            <div class="text-sm">
                                                <A
                                                    href={`/sboms/${entry().from.id}`}
                                                    class="mono"
                                                >
                                                    {entry().from
                                                        .subjectVersion ??
                                                        entry().from.id.slice(
                                                            0,
                                                            8,
                                                        )}
                                                </A>
                                                {" \u2192 "}
                                                <A
                                                    href={`/sboms/${entry().to.id}`}
                                                    class="mono"
                                                >
                                                    {entry().to
                                                        .subjectVersion ??
                                                        entry().to.id.slice(
                                                            0,
                                                            8,
                                                        )}
                                                </A>
                                                <span class="text-muted">
                                                    {" "}
                                                    (
                                                    {new Date(
                                                        entry().to.createdAt,
                                                    ).toLocaleDateString()}
                                                    )
                                                </span>
                                            </div>
                                            <div class="changelog-summary">
                                                <Show
                                                    when={
                                                        entry().summary.added >
                                                        0
                                                    }
                                                >
                                                    <span class="badge badge-success">
                                                        +{entry().summary.added}{" "}
                                                        added
                                                    </span>
                                                </Show>
                                                <Show
                                                    when={
                                                        entry().summary
                                                            .removed > 0
                                                    }
                                                >
                                                    <span class="badge badge-danger">
                                                        -
                                                        {
                                                            entry().summary
                                                                .removed
                                                        }{" "}
                                                        removed
                                                    </span>
                                                </Show>
                                                <Show
                                                    when={
                                                        entry().summary
                                                            .modified > 0
                                                    }
                                                >
                                                    <span class="badge badge-warning">
                                                        ~
                                                        {
                                                            entry().summary
                                                                .modified
                                                        }{" "}
                                                        modified
                                                    </span>
                                                </Show>
                                            </div>
                                        </div>

                                        <Show
                                            when={entry().changes.length > 0}
                                            fallback={
                                                <EmptyState
                                                    title="No differences"
                                                    message="These two SBOMs have identical components."
                                                />
                                            }
                                        >
                                            <div class="table-wrapper">
                                                <table>
                                                    <thead>
                                                        <tr>
                                                            <th>Change</th>
                                                            <th>Name</th>
                                                            <th>Version</th>
                                                            <th>PURL</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <For
                                                            each={
                                                                entry().changes
                                                            }
                                                        >
                                                            {(change) => (
                                                                <tr>
                                                                    <td>
                                                                        <span
                                                                            class={`badge ${
                                                                                change.type ===
                                                                                "added"
                                                                                    ? "badge-success"
                                                                                    : change.type ===
                                                                                        "removed"
                                                                                      ? "badge-danger"
                                                                                      : "badge-warning"
                                                                            }`}
                                                                        >
                                                                            {
                                                                                change.type
                                                                            }
                                                                        </span>
                                                                    </td>
                                                                    <td>
                                                                        {change.group
                                                                            ? `${change.group}/`
                                                                            : ""}
                                                                        {
                                                                            change.name
                                                                        }
                                                                    </td>
                                                                    <td class="mono">
                                                                        <Show
                                                                            when={
                                                                                change.previousVersion
                                                                            }
                                                                        >
                                                                            <span class="text-muted">
                                                                                {
                                                                                    change.previousVersion
                                                                                }
                                                                            </span>
                                                                            {
                                                                                " \u2192 "
                                                                            }
                                                                        </Show>
                                                                        {change.version ??
                                                                            "\u2014"}
                                                                    </td>
                                                                    <td
                                                                        class="mono truncate text-muted"
                                                                        title={
                                                                            change.purl ??
                                                                            undefined
                                                                        }
                                                                    >
                                                                        {change.purl
                                                                            ? purlDisplayName(
                                                                                  change.purl,
                                                                              )
                                                                            : "\u2014"}
                                                                    </td>
                                                                </tr>
                                                            )}
                                                        </For>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </Show>
                                    </div>
                                </>
                            )}
                        </Show>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
