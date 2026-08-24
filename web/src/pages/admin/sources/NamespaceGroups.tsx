import { For, Show, createMemo } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { Namespace, Registry, Source } from "~/api/client";
import { Card, CardHeader } from "~/components/ui";

/** One namespace's ingest channels, split by what there is to configure. */
export interface NamespaceGroup {
    namespace: string;
    namespaceID?: string;
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
    const groupFor = (name: string, id: string): NamespaceGroup => {
        let g = groups.get(name);
        if (g === undefined) {
            g = { namespace: name, namespaceID: id, registries: [], uploads: [] };
            groups.set(name, g);
        }
        return g;
    };

    for (const src of sources) {
        // namespace_name is documented as list-only; fall back to the id so
        // a heading is never blank.
        const g = groupFor(src.namespace_name ?? src.namespace_id, src.namespace_id);
        const reg = registriesByID.get(src.id);
        if (src.kind === "oci_registry" && reg !== undefined) {
            g.registries.push(reg);
        } else if (src.kind === "upload") {
            g.uploads.push(src);
        }
    }

    return [...groups.values()].sort((a, b) => a.namespace.localeCompare(b.namespace));
}

/**
 * NamespaceGroups lists every visible source under the namespace that owns it.
 *
 * Each namespace used to get its own `<DataTable>`, which meant the nine-column
 * header was re-rendered once per group — roughly ten identical headers down
 * the page for groups that were mostly one row each. There is one table now,
 * and the namespace is a spanning group row inside it (ocidex-ag4q.38).
 */
export function NamespaceGroups(props: {
    columns: Column<Registry>[];
    registries: Registry[];
    sources: Source[];
    /** Namespaces visible to the caller, used to annotate each heading. */
    namespaces?: Namespace[];
    loading: boolean;
    isError: boolean;
    error?: unknown;
}) {
    const groups = createMemo(() => groupByNamespace(props.registries, props.sources));

    const namespaceByName = createMemo(() => {
        const byID = new Map<string, Namespace>();
        for (const ns of props.namespaces ?? []) byID.set(ns.id, ns);

        const byName = new Map<string, Namespace>();
        for (const group of groups()) {
            const ns = group.namespaceID !== undefined ? byID.get(group.namespaceID) : undefined;
            if (ns !== undefined) byName.set(group.namespace, ns);
        }
        return byName;
    });

    // Flattened in group order, so each namespace's registries are one
    // consecutive run — which is what DataTable's groupBy labels.
    const registryRows = createMemo(() => groups().flatMap((g) => g.registries));

    const namespaceOfRegistry = createMemo(() => {
        const byID = new Map<string, string>();
        for (const group of groups()) {
            for (const reg of group.registries) byID.set(reg.id, group.namespace);
        }
        return byID;
    });

    /**
     * Upload sources have no OCI configuration at all — no URL, no scan mode,
     * no webhook. Listing them in the registry table would be a row of
     * em-dashes claiming those settings exist but are unset, so they get their
     * own short list, each line naming its namespace.
     */
    const uploadRows = createMemo(() =>
        groups().flatMap((g) => g.uploads.map((source) => ({ namespace: g.namespace, source }))),
    );

    const heading = (name: string, count: number) => {
        const ns = () => namespaceByName().get(name);
        return (
            <span data-testid="namespace-heading" class="ns-group-heading">
                <Show when={ns()} fallback={name}>
                    <A href="/admin/namespaces">{name}</A>
                </Show>{" "}
                <span class="group-header-count">{count}</span>
                <Show when={ns()}>
                    {(namespace) => (
                        <>
                            {" "}
                            <span
                                data-testid="namespace-visibility"
                                class={`badge ${namespace().visibility === "public" ? "badge-success" : ""}`}
                            >
                                {namespace().visibility}
                            </span>
                            <Show when={namespace().owner_username}>
                                {(owner) => (
                                    <span class="text-muted text-sm ns-group-owner">
                                        owned by {owner()}
                                    </span>
                                )}
                            </Show>
                        </>
                    )}
                </Show>
            </span>
        );
    };

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
                when={registryRows().length > 0 || uploadRows().length > 0}
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
                <Show when={registryRows().length > 0}>
                    <DataTable
                        columns={props.columns}
                        rows={registryRows()}
                        loading={false}
                        isError={false}
                        emptyTitle="No sources found"
                        groupBy={{
                            // The namespace row is what says who owns these
                            // sources and whether they are public — the source
                            // rows themselves carry neither (ADR-039).
                            key: (reg) => namespaceOfRegistry().get(reg.id) ?? "",
                            header: (name, count) => heading(name, count),
                        }}
                    />
                </Show>

                <Show when={uploadRows().length > 0}>
                    <Card style={{ "margin-top": registryRows().length > 0 ? "0.75rem" : "0" }}>
                        <CardHeader title="Upload sources" count={uploadRows().length} />
                        <For each={uploadRows()}>
                            {(row) => (
                                <div
                                    data-testid="upload-source"
                                    style={{
                                        display: "flex",
                                        "align-items": "center",
                                        gap: "0.5rem",
                                        padding: "0.35rem 0",
                                    }}
                                >
                                    <span class="badge">upload</span>
                                    <span class="text-muted text-sm">{row.namespace}</span>
                                    <span>{row.source.name}</span>
                                    <span class="text-muted text-sm">
                                        SBOMs pushed to the API — nothing to configure
                                    </span>
                                </div>
                            )}
                        </For>
                    </Card>
                </Show>
            </Show>
        </Show>
    );
}
