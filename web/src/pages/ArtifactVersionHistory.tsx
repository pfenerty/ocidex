import { For, Show, createSignal } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useArtifact, useArtifactSBOMs } from "~/api/queries";
import type { SBOMSummary } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import { relativeDate, plural, formatDateTime } from "~/utils/format";

export default function ArtifactVersionHistory() {
    const params = useParams<{ id: string; version: string }>();
    const version = () => decodeURIComponent(params.version);

    const artifactQuery = useArtifact(() => params.id);

    const sbomsQuery = useArtifactSBOMs(
        () => params.id,
        () => ({ image_version: version(), limit: 200 }),
    );

    const [selectedArch, setSelectedArch] = createSignal<string | undefined>("amd64");

    // Group SBOMs by exact build timestamp, preserving DESC order from API.
    const groups = () => {
        const sboms = sbomsQuery.data?.data ?? [];
        const order: string[] = [];
        const map = new Map<string, SBOMSummary[]>();
        for (const sbom of sboms) {
            const key = sbom.buildDate !== undefined
                ? new Date(sbom.buildDate).toISOString()
                : new Date(sbom.createdAt).toISOString();
            if (!map.has(key)) {
                order.push(key);
                map.set(key, []);
            }
            map.get(key)?.push(sbom);
        }
        return { order, map };
    };

    const allArchs = () => {
        const archs = new Set<string>();
        for (const sboms of groups().map.values()) {
            for (const s of sboms) {
                if (s.architecture !== undefined) archs.add(s.architecture);
            }
        }
        return [...archs].sort();
    };

    const filteredOrder = () => {
        const arch = selectedArch();
        if (arch === undefined) return groups().order;
        return groups().order.filter((key) =>
            (groups().map.get(key) ?? []).some((s) => s.architecture === arch),
        );
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
                        <p class="text-muted">Build history for this version</p>
                    </div>
                </div>
            </div>

            <Show when={!sbomsQuery.isLoading} fallback={<Loading />}>
                <Show
                    when={!sbomsQuery.isError}
                    fallback={<ErrorBox error={sbomsQuery.error} />}
                >
                    <Show
                        when={groups().order.length > 0}
                        fallback={
                            <EmptyState
                                title="No builds found"
                                message="No SBOMs found for this version."
                            />
                        }
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

                        <For each={filteredOrder()}>
                            {(dateKey) => (
                                <BuildEntry
                                    dateKey={dateKey}
                                    sboms={groups().map.get(dateKey) ?? []}
                                    selectedArch={selectedArch()}
                                />
                            )}
                        </For>
                    </Show>
                </Show>
            </Show>
        </>
    );
}

function BuildEntry(props: {
    dateKey: string;
    sboms: SBOMSummary[];
    selectedArch: string | undefined;
}) {
    const [open, setOpen] = createSignal(false);

    const visibleSboms = () =>
        props.selectedArch !== undefined
            ? props.sboms.filter((s) => s.architecture === props.selectedArch)
            : props.sboms;

    const total = () =>
        visibleSboms().reduce((n, s) => n + (s.componentCount ?? 0), 0);

    return (
        <div class="changelog-entry">
            <div
                class="changelog-entry-header"
                style={{ cursor: "pointer", "user-select": "none" }}
                onClick={() => setOpen((o) => !o)}
            >
                <div
                    class="text-sm"
                    style={{ display: "flex", "align-items": "center", gap: "0.5rem" }}
                >
                    <span
                        style={{
                            display: "inline-block",
                            "font-size": "0.6rem",
                            transition: "transform 0.15s",
                            transform: open() ? "rotate(90deg)" : "rotate(0deg)",
                            color: "var(--color-text-dim)",
                        }}
                    >
                        ▶
                    </span>
                    <span class="text-muted" title={formatDateTime(props.dateKey)}>
                        {relativeDate(props.dateKey)}
                    </span>
                </div>
                <div class="changelog-summary">
                    <For each={visibleSboms()}>
                        {(s) => (
                            <span class="badge badge-primary">
                                {s.architecture ?? "unknown"}
                            </span>
                        )}
                    </For>
                    <Show when={total() > 0}>
                        <span class="text-muted text-sm">
                            {plural(total(), "component")}
                        </span>
                    </Show>
                </div>
            </div>
            <Show when={open()}>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Architecture</th>
                                <th>Components</th>
                                <th>SBOM</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={visibleSboms()}>
                                {(s) => (
                                    <tr>
                                        <td>
                                            <span class="badge badge-primary">
                                                {s.architecture ?? "unknown"}
                                            </span>
                                        </td>
                                        <td>
                                            <Show
                                                when={(s.componentCount ?? 0) > 0}
                                                fallback={
                                                    <span class="text-muted">—</span>
                                                }
                                            >
                                                {plural(s.componentCount ?? 0, "component")}
                                            </Show>
                                        </td>
                                        <td>
                                            <A
                                                href={`/sboms/${s.id}`}
                                                class="mono text-sm"
                                            >
                                                {s.id}
                                            </A>
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </Show>
        </div>
    );
}
