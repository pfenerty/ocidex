import { createSignal, createMemo, Show, For } from "solid-js";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import {
    ComponentNameCell,
    VersionCell,
    TypeBadge,
    PurlLink,
    VulnCountBadges,
} from "~/components/cells";
import { plural } from "~/utils/format";
import { parsePurl } from "~/utils/purl";
import { componentHref } from "./componentHref";
import { DependencyTreeView } from "./DependencyTreeView";


/* ------------------------------------------------------------------ */
/*  Packages Tab                                                       */
/* ------------------------------------------------------------------ */

export function PackagesTab(props: {
    components: ComponentSummary[];
    depsGraph?: { edges: DependencyEdge[]; nodes: ComponentSummary[] };
    // Keyset load-more over the (server-paginated) component list. The text and
    // type filters apply only to already-loaded packages.
    hasMore?: boolean;
    loadingMore?: boolean;
    onLoadMore?: () => void;
}) {
    const [filter, setFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("all");
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");

    const ecoType = (c: ComponentSummary) =>
        parsePurl(c.purl ?? "")?.type ?? c.type;

    const packages = createMemo(() =>
        props.components.filter((c) => c.type !== "file"),
    );

    const types = createMemo(() => {
        const set = new Set(packages().map(ecoType));
        return Array.from(set).sort();
    });

    const filtered = createMemo(() => {
        const comps = packages();
        if (comps.length === 0) return [];
        const q = filter().toLowerCase();
        const t = typeFilter();
        return comps.filter((c) => {
            if (t !== "all" && ecoType(c) !== t) return false;
            if (!q) return true;
            const display =
                (c.group !== undefined && c.group !== "" ? `${c.group}/` : "") +
                c.name +
                (c.version !== undefined && c.version !== "" ? `@${c.version}` : "");
            return (
                display.toLowerCase().includes(q) ||
                (c.purl?.toLowerCase().includes(q) ?? false)
            );
        });
    });

    const updateFilter = (v: string) => setFilter(v);
    const updateType = (v: string) => setTypeFilter(v);

    const hasTree = () => (props.depsGraph?.edges.length ?? 0) > 0;
    const effectiveMode = () => (hasTree() ? viewMode() : "list");

    const columns: Column<ComponentSummary>[] = [
        {
            header: "Name",
            render: (c) => (
                <ComponentNameCell
                    name={c.name}
                    group={c.group}
                    href={componentHref(c.name, c.group, c.version)}
                />
            ),
        },
        {
            header: "Version",
            render: (c) => <VersionCell version={c.version} />,
        },
        {
            header: "Type",
            render: (c) => <TypeBadge type={ecoType(c)} />,
        },
        {
            header: "Vulns",
            render: (c) => (
                <VulnCountBadges
                    criticalCount={c.criticalCount}
                    highCount={c.highCount}
                    mediumCount={c.mediumCount}
                    lowCount={c.lowCount}
                    unknownCount={c.unknownCount}
                />
            ),
        },
        {
            header: "Package URL",
            render: (c) =>
                c.purl !== undefined ? (
                    <PurlLink purl={c.purl} showBadge />
                ) : (
                    <span class="text-muted">—</span>
                ),
        },
    ];

    return (
        <Show
            when={packages().length > 0}
            fallback={
                <EmptyState
                    title="No packages"
                    message="This SBOM has no components."
                />
            }
        >
            <>
                <div class="search-bar mb-4" style={{ "flex-wrap": "wrap" }}>
                    <Show when={effectiveMode() === "list"}>
                        <input
                            type="text"
                            placeholder="Filter packages…"
                            value={filter()}
                            onInput={(e) => updateFilter(e.currentTarget.value)}
                            style={{ flex: "1", "min-width": "200px" }}
                        />
                        <select
                            value={typeFilter()}
                            onChange={(e) => updateType(e.currentTarget.value)}
                        >
                            <option value="all">
                                All types ({packages().length})
                            </option>
                            <For each={types()}>
                                {(t) => <option value={t}>{t}</option>}
                            </For>
                        </select>
                    </Show>
                    <span class="text-muted text-sm">
                        {effectiveMode() === "list"
                            ? filtered().length === packages().length
                                ? plural(filtered().length, "package")
                                : `${filtered().length} of ${packages().length} packages`
                            : plural(packages().length, "package")}
                    </span>
                    <Show when={hasTree()}>
                        <div class="btn-group" style={{ "margin-left": "auto" }}>
                            <button
                                class={`btn btn-sm${effectiveMode() === "tree" ? " active" : ""}`}
                                onClick={() => setViewMode("tree")}
                            >
                                Tree
                            </button>
                            <button
                                class={`btn btn-sm${effectiveMode() === "list" ? " active" : ""}`}
                                onClick={() => setViewMode("list")}
                            >
                                List
                            </button>
                        </div>
                    </Show>
                </div>

                <Show
                    when={effectiveMode() === "tree" ? props.depsGraph : undefined}
                    keyed
                    fallback={
                        <DataTable
                            columns={columns}
                            rows={filtered()}
                            loading={false}
                            isError={false}
                            emptyTitle="No packages match"
                            emptyMessage="Try a different filter or type."
                            loadMore={{
                                hasMore: props.hasMore ?? false,
                                loading: props.loadingMore ?? false,
                                onClick: () => props.onLoadMore?.(),
                            }}
                        />
                    }
                >
                    {(graph) => (
                        <div class="card">
                            <DependencyTreeView graph={graph} />
                        </div>
                    )}
                </Show>
            </>
        </Show>
    );
}
