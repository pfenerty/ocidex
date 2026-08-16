import { For, Show, createMemo } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { Registry, Source } from "~/api/client";

/** One namespace's ingest channels, split by what there is to configure. */
export interface NamespaceGroup {
    namespace: string;
    registries: Registry[];
    uploads: Source[];
}

/**
 * groupByNamespace organises sources by their owning namespace (ADR-039).
 * Registry rows join to their source on `id` — migration 00053 made
 * registry.id a foreign key *onto* source.id, so they are the same value and
 * no extra lookup is needed.
 */
export function groupByNamespace(registries: Registry[], sources: Source[]): NamespaceGroup[] {
    const registriesByID = new Map<string, Registry>();
    for (const reg of registries) {
        registriesByID.set(reg.id, reg);
    }

    const groups = new Map<string, NamespaceGroup>();
    const groupFor = (name: string): NamespaceGroup => {
        let g = groups.get(name);
        if (g === undefined) {
            g = { namespace: name, registries: [], uploads: [] };
            groups.set(name, g);
        }
        return g;
    };

    for (const src of sources) {
        // namespace_name is documented as list-only; fall back to the id so
        // a heading is never blank.
        const g = groupFor(src.namespace_name ?? src.namespace_id);
        const reg = registriesByID.get(src.id);
        if (src.kind === "oci_registry" && reg !== undefined) {
            g.registries.push(reg);
        } else if (src.kind === "upload") {
            g.uploads.push(src);
        }
    }

    return [...groups.values()].sort((a, b) => a.namespace.localeCompare(b.namespace));
}

export function NamespaceGroups(props: {
    columns: Column<Registry>[];
    registries: Registry[];
    sources: Source[];
    loading: boolean;
    isError: boolean;
    error?: unknown;
}) {
    const groups = createMemo(() => groupByNamespace(props.registries, props.sources));

    return (
        <Show
            when={!props.loading && !props.isError}
            fallback={
                <DataTable
                    columns={props.columns}
                    rows={undefined}
                    loading={props.loading}
                    isError={props.isError}
                    error={props.error}
                    emptyTitle="No sources found"
                />
            }
        >
            <Show
                when={groups().length > 0}
                fallback={
                    <DataTable
                        columns={props.columns}
                        rows={[]}
                        loading={false}
                        isError={false}
                        emptyTitle="No sources found"
                    />
                }
            >
                <For each={groups()}>
                    {(group) => (
                        <div style={{ "margin-bottom": "1.5rem" }}>
                            <h3
                                data-testid="namespace-heading"
                                style={{ "font-size": "1rem", "margin-bottom": "0.5rem" }}
                            >
                                {group.namespace}{" "}
                                <span class="group-header-count">{group.registries.length + group.uploads.length}</span>
                            </h3>

                            <Show when={group.registries.length > 0}>
                                <DataTable
                                    columns={props.columns}
                                    rows={group.registries}
                                    loading={false}
                                    isError={false}
                                    emptyTitle="No registries found"
                                />
                            </Show>

                            {/* Upload sources have no OCI configuration at all — no URL,
                                no scan mode, no webhook. Listing them in the registry table
                                would be a row of em-dashes claiming those settings exist
                                but are unset, so they get their own short list instead. */}
                            <Show when={group.uploads.length > 0}>
                                <div class="card" style={{ "margin-top": group.registries.length > 0 ? "0.75rem" : "0" }}>
                                    <For each={group.uploads}>
                                        {(src) => (
                                            <div
                                                data-testid="upload-source"
                                                style={{ display: "flex", "align-items": "center", gap: "0.5rem", padding: "0.35rem 0" }}
                                            >
                                                <span class="badge">upload</span>
                                                <span>{src.name}</span>
                                                <span style={{ color: "var(--color-text-muted)", "font-size": "0.85rem" }}>
                                                    SBOMs pushed to the API — nothing to configure
                                                </span>
                                            </div>
                                        )}
                                    </For>
                                </div>
                            </Show>
                        </div>
                    )}
                </For>
            </Show>
        </Show>
    );
}
