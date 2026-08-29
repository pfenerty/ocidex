import { createSignal, createMemo, Show, For } from "solid-js";
import type { ComponentSummary, DependencyEdge } from "~/api/client";
import { EmptyState } from "~/components/Feedback";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import {
    ComponentNameCell,
    VersionCell,
    TypeBadge,
    PurlLink,
    VulnCountBadges,
} from "~/components/cells";
import { plural } from "~/utils/format";
import { parsePurl } from "~/utils/purl";
import { Button, ButtonGroup, Card, Tooltip } from "~/components/ui";
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
    /**
     * The server's package count for the whole SBOM, and its count of every
     * component including files. `components` is only the window loaded so far,
     * so its length is not the figure to show — the page used to render it as
     * "200 packages" directly beneath a tile and a tab that both said 958.
     */
    totalCount?: number;
    componentCount?: number;
    /**
     * Server-side sort, owned by the page because the query that pages this
     * list lives there. Only the severity column is sortable: the counts are
     * not in the loaded window's shape, so sorting them client-side would
     * order the first 200 rows and call it the worst packages in the SBOM.
     */
    sortBy?: string;
    sortDir?: SortDir;
    onSort?: (sortKey: string, dir: SortDir) => void;
}) {
    const [filter, setFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("all");
    const [viewMode, setViewMode] = createSignal<"tree" | "list">("tree");
    // One filter across both view modes: the reader asking "what is vulnerable
    // in here" should not have to re-apply it after switching between the tree
    // and the list, and the answer is the same set either way.
    const [vulnerableOnly, setVulnerableOnly] = createSignal(false);

    const ecoType = (c: ComponentSummary) =>
        parsePurl(c.purl ?? "")?.type ?? c.type;

    const vulnTotal = (c: ComponentSummary) =>
        (c.criticalCount ?? 0) +
        (c.highCount ?? 0) +
        (c.mediumCount ?? 0) +
        (c.lowCount ?? 0) +
        (c.unknownCount ?? 0);

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
            if (vulnerableOnly() && vulnTotal(c) === 0) return false;
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

    // The authoritative figure is the server's count for the whole SBOM, not the
    // length of the window this tab has loaded. Fall back to the loaded length
    // only when the caller passes no total.
    const total = () => props.totalCount ?? packages().length;
    const allLoaded = () => packages().length >= total();

    const loadedLabel = () =>
        allLoaded()
            ? plural(total(), "package")
            : `${packages().length} of ${total()} packages loaded`;

    // Filtering is client-side over the loaded rows, so a filtered count is
    // quoted against those rows and says so, rather than against the total.
    const countLabel = () =>
        effectiveMode() === "list" && filtered().length !== packages().length
            ? `${filtered().length} of ${packages().length} loaded packages`
            : loadedLabel();

    // The two views draw from different sources — the list from the paged
    // component window, the tree from the whole dependency graph — so the
    // toggle is only pointless when *neither* has anything to show.
    const hasVulnerable = () =>
        packages().some((c) => vulnTotal(c) > 0) ||
        (props.depsGraph?.nodes.some((c) => vulnTotal(c) > 0) ?? false);

    const countExplanation = () => {
        const all = props.componentCount ?? 0;
        const files = all - total();
        const parts = ["Packages are this SBOM's components excluding file entries."];
        if (files > 0) {
            parts.push(`${all} components in total, ${files} of them files.`);
        }
        if (!allLoaded()) {
            parts.push("Filtering and type counts apply to the loaded rows only.");
        }
        if (vulnerableOnly() && effectiveMode() === "tree") {
            parts.push("The tree keeps the path to each vulnerable package, so an unaffected parent still appears.");
        }
        return parts.join(" ");
    };

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
            sortKey: "severity",
            sortType: "numeric",
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
                            <option value="all">All types</option>
                            <For each={types()}>
                                {(t) => <option value={t}>{t}</option>}
                            </For>
                        </select>
                    </Show>
                    <span class="text-muted text-sm">
                        <Tooltip content={countExplanation()}>{countLabel()}</Tooltip>
                    </span>
                    {/* Outside the list-only block: this one applies to both
                        views, and losing it on a view switch is exactly the
                        thing that makes a filter feel like it belongs to the
                        widget rather than to the question. */}
                    <Button
                        size="sm"
                        active={vulnerableOnly()}
                        aria-pressed={vulnerableOnly()}
                        disabled={!hasVulnerable()}
                        title={
                            hasVulnerable()
                                ? undefined
                                : "No loaded package has a recorded vulnerability"
                        }
                        onClick={() => setVulnerableOnly((v) => !v)}
                    >
                        Vulnerable only
                    </Button>
                    <Show when={hasTree()}>
                        <ButtonGroup class="ml-auto">
                            <Button
                                size="sm"
                                active={effectiveMode() === "tree"}
                                onClick={() => setViewMode("tree")}
                            >
                                Tree
                            </Button>
                            <Button
                                size="sm"
                                active={effectiveMode() === "list"}
                                onClick={() => setViewMode("list")}
                            >
                                List
                            </Button>
                        </ButtonGroup>
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
                            sortBy={props.sortBy}
                            sortDir={props.sortDir}
                            onSort={props.onSort}
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
                        <Card>
                            <DependencyTreeView graph={graph} vulnerableOnly={vulnerableOnly()} />
                        </Card>
                    )}
                </Show>
            </>
        </Show>
    );
}
