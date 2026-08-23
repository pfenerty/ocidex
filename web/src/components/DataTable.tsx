import "./DataTable.css";
import { Show, For, createSignal, createMemo, createEffect } from "solid-js";
import type { JSX } from "solid-js";
import { ErrorBox, EmptyState } from "~/components/Feedback";
import { Skeleton } from "~/components/Skeleton";
import Pagination from "~/components/Pagination";
import LoadMore from "~/components/LoadMore";
import type { PaginationMeta } from "~/api/client";
import { Card } from "~/components/ui";

export type SortDir = "asc" | "desc";

export interface Column<T> {
    /**
     * JSX rather than string so a column can colour or decorate its own label.
     * The enricher health matrix needs it: its four state columns are the same
     * four colours as the state badges in the table below, and a header that
     * cannot carry that is a header that has to be hand-rolled.
     */
    header: JSX.Element;
    sortKey?: string;
    /** Default sort direction when this column becomes active. Default "text". */
    sortType?: "text" | "numeric";
    /** Required for client-side sort mode (when onSort is not provided). */
    sortValue?: (row: T) => string | number;
    align?: "left" | "right";
    /**
     * Extra classes for this column's `th` and every one of its `td`s. Column
     * width and per-column typography live here rather than in an inline style
     * on one hand-written `<th>`, which is where they used to live and where no
     * stylesheet could reach them.
     */
    class?: string;
    render: (row: T) => JSX.Element;
}

export interface DataTableProps<T> {
    columns: Column<T>[];
    /** undefined = no data loaded yet (first load). */
    rows: T[] | undefined;
    /** Pass the query's isFetching, not isLoading, so first-load and refetch can be told apart. */
    loading: boolean;
    isError: boolean;
    error?: unknown;
    emptyTitle: string;
    emptyMessage?: JSX.Element;
    /** Controlled (server-side) sort mode only. */
    sortBy?: string;
    sortDir?: SortDir;
    /** Presence of onSort selects controlled mode; absence selects client-side sort. */
    onSort?: (sortKey: string, dir: SortDir) => void;
    pagination?: {
        pagination: PaginationMeta;
        onPageChange: (offset: number) => void;
    };
    loadMore?: {
        hasMore: boolean;
        loading: boolean;
        onClick: () => void;
    };
    /** Number of shimmer rows to show on first load. Default 8. */
    skeletonRows?: number;
    /**
     * Content rendered inside the card above the table — a `<CardHeader>`, a
     * line of explanation, or both.
     *
     * Without this, a table that needs a title has to be hand-rolled inside its
     * own `<Card>`, because DataTable emits one of its own and nesting two is
     * two borders and two lots of padding. It is deliberately rendered in the
     * error and empty branches too: the drift feed's caption is the sentence
     * saying the feed is regression-only, and an empty feed is exactly when the
     * reader most needs to be told that.
     */
    caption?: JSX.Element;
    /** Extra classes for the card the table is rendered in. */
    class?: string;
    /**
     * Render without the surrounding `<Card>`, for a table that is already
     * inside one — ProvenanceCard's collapsible verification history sits in
     * the card the component itself emits, and a second card there is two
     * borders and two lots of padding.
     */
    bare?: boolean;
    /**
     * Row-level behaviour, which per-cell `render` cannot reach. Both tree views
     * toggle a node by clicking anywhere on its row.
     *
     * Setting this also makes the row focusable and Enter/Space-activatable —
     * the hand-rolled versions were mouse-only, so an expandable tree was
     * unreachable by keyboard.
     */
    onRowClick?: (row: T) => void;
    /**
     * Extra classes per row. Use real classes, not inline styles: the two tree
     * views spelled `cursor` and `opacity` inline on every row, which no
     * stylesheet and no theme could reach.
     */
    rowClass?: (row: T) => string | undefined;
    /**
     * Which rows `onRowClick` applies to. Default: all of them.
     *
     * Expandable tables emit two row shapes — the parent that toggles and the
     * children it reveals — and giving the children a pointer cursor and a tab
     * stop that does nothing is worse than not offering them at all.
     */
    rowClickable?: (row: T) => boolean;
    /**
     * Emit a spanning header row whenever `key` changes between consecutive
     * rows. The rows arrive already ordered by their group — this only labels
     * the runs, it does not reorder them.
     */
    groupBy?: {
        key: (row: T) => string;
        header: (key: string, count: number) => JSX.Element;
    };
}

function cellClass<T>(col: Column<T>): string {
    return [col.align === "right" ? "text-right" : "", col.class ?? ""]
        .filter((c) => c !== "")
        .join(" ");
}

function defaultDirFor(col: Pick<Column<unknown>, "sortType">): SortDir {
    return col.sortType === "numeric" ? "desc" : "asc";
}

function compareValues(a: string | number, b: string | number): number {
    if (typeof a === "number" && typeof b === "number") return a - b;
    return String(a).localeCompare(String(b));
}

export default function DataTable<T>(props: DataTableProps<T>): JSX.Element {
    if (import.meta.env.DEV) {
        createEffect(() => {
            if (props.pagination && props.loadMore) {
                console.warn(
                    "DataTable: pagination and loadMore are mutually exclusive; pagination will be used.",
                );
            }
        });
    }

    const [clientSortBy, setClientSortBy] = createSignal<string | undefined>(undefined);
    const [clientSortDir, setClientSortDir] = createSignal<SortDir>("asc");

    const sortBy = () => (props.onSort ? props.sortBy : clientSortBy());
    const sortDir = () => (props.onSort ? props.sortDir : clientSortDir());

    const handleSort = (col: Column<T>) => {
        if (col.sortKey === undefined) return;
        const nextDir: SortDir =
            sortBy() === col.sortKey
                ? sortDir() === "asc"
                    ? "desc"
                    : "asc"
                : defaultDirFor(col);

        if (props.onSort) {
            props.onSort(col.sortKey, nextDir);
        } else {
            setClientSortBy(col.sortKey);
            setClientSortDir(nextDir);
        }
    };

    const sortedRows = createMemo(() => {
        const rows = props.rows;
        if (rows === undefined || props.onSort) return rows;
        const key = clientSortBy();
        if (key === undefined) return rows;
        const col = props.columns.find((c) => c.sortKey === key);
        if (col?.sortValue === undefined) return rows;
        const getValue = col.sortValue;
        const dir = clientSortDir();
        return [...rows].sort((a, b) => {
            const cmp = compareValues(getValue(a), getValue(b));
            return dir === "asc" ? cmp : -cmp;
        });
    });

    const isFirstLoad = () => props.loading && props.rows === undefined;
    const isRefetching = () => props.loading && props.rows !== undefined;

    const visibleRows = createMemo(() => {
        const rows = sortedRows();
        return rows !== undefined && rows.length > 0 ? rows : undefined;
    });

    const sortArrow = (col: Column<T>) => {
        if (sortBy() !== col.sortKey) return null;
        return <span class="sort-arrow">{sortDir() === "asc" ? "▲" : "▼"}</span>;
    };

    const skeletonBody = (count: number) => (
        <For each={Array.from({ length: count })}>
            {() => (
                <tr>
                    <For each={props.columns}>
                        {(col) => (
                            <td class={cellClass(col)}>
                                <Skeleton height="0.85em" />
                            </td>
                        )}
                    </For>
                </tr>
            )}
        </For>
    );

    const dataRow = (row: T) => {
        const clickable = props.onRowClick !== undefined && (props.rowClickable?.(row) ?? true);
        const activate = () => props.onRowClick?.(row);
        return (
            // One `class` string, not `class` + `classList`: Solid sets className
            // first and then diffs classList against its own previous state, so
            // a dynamic `class` beside a `classList` silently wipes it. The row
            // kept its tabindex and lost its pointer cursor — verified in the
            // browser, invisible to tsc and to a test that only counts rows.
            <tr
                class={
                    [props.rowClass?.(row), clickable ? "row-clickable" : ""]
                        .filter((c) => c !== undefined && c !== "")
                        .join(" ") || undefined
                }
                tabIndex={clickable ? 0 : undefined}
                onClick={clickable ? activate : undefined}
                onKeyDown={(e: KeyboardEvent) => {
                    if (!clickable) return;
                    if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        activate();
                    }
                }}
            >
                <For each={props.columns}>
                    {(col) => (
                        <td class={cellClass(col)}>{col.render(row)}</td>
                    )}
                </For>
            </tr>
        );
    };

    /**
     * Rows interleaved with their group headers. Runs are consecutive by
     * contract — a group whose rows are not adjacent gets two headers, which is
     * the honest rendering of unsorted input rather than a silent regroup.
     */
    const grouped = (rows: T[]): { key: string; items: T[] }[] => {
        const by = props.groupBy;
        if (by === undefined) return [{ key: "", items: rows }];
        const out: { key: string; items: T[] }[] = [];
        for (const row of rows) {
            const key = by.key(row);
            if (out.length > 0 && out[out.length - 1].key === key) {
                out[out.length - 1].items.push(row);
            } else {
                out.push({ key, items: [row] });
            }
        }
        return out;
    };

    const realBody = (rows: T[]) => (
        <For each={grouped(rows)}>
            {(group) => (
                <>
                    <Show when={props.groupBy}>
                        {(by) => (
                            <tr class="group-header-row">
                                <td colspan={props.columns.length}>
                                    {by().header(group.key, group.items.length)}
                                </td>
                            </tr>
                        )}
                    </Show>
                    <For each={group.items}>{(row) => dataRow(row)}</For>
                </>
            )}
        </For>
    );

    const shellContent = (body: () => JSX.Element) => (
        <>
            {props.caption}
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <For each={props.columns}>
                                {(col) => (
                                    <th
                                        class={
                                            (col.sortKey !== undefined ? "th-sortable " : "") +
                                            cellClass(col)
                                        }
                                        onClick={() => handleSort(col)}
                                    >
                                        {col.header}
                                        {col.sortKey !== undefined && sortArrow(col)}
                                    </th>
                                )}
                            </For>
                        </tr>
                    </thead>
                    <tbody>{body()}</tbody>
                </table>
            </div>
            <Show when={props.pagination}>
                {(p) => <Pagination pagination={p().pagination} onPageChange={p().onPageChange} />}
            </Show>
            <Show when={!props.pagination && props.loadMore}>
                {(lm) => (
                    <LoadMore hasMore={lm().hasMore} loading={lm().loading} onClick={lm().onClick} />
                )}
            </Show>
        </>
    );

    // body is a thunk so the tbody stays reactive: reading rows()/isRefetching()
    // inside the {body()} expression lets Solid re-render just the tbody on
    // pagination, sort, and refetch without rebuilding the card/headers.
    //
    // aria-busy rather than a swap to shimmer: a refetch on this table is
    // almost always a sort, a page, or a keystroke in a debounced filter, and
    // blanking the rows the reader is mid-sentence in loses their place to
    // announce something they already know they asked for. The rows stay put
    // and dim; a screen reader gets the busy state it would otherwise have to
    // infer from the content vanishing.
    const tableShell = (body: () => JSX.Element) =>
        props.bare === true ? (
            <div
                class={props.class}
                classList={{ "table-refetching": isRefetching() }}
                aria-busy={isRefetching()}
            >
                {shellContent(body)}
            </div>
        ) : (
            <Card
                class={props.class}
                classList={{ "table-refetching": isRefetching() }}
                aria-busy={isRefetching()}
            >
                {shellContent(body)}
            </Card>
        );

    // Error and empty states are bare by default — that is how every existing
    // call site renders — but a captioned table has to keep its caption in
    // those branches or the section loses its title exactly when it is emptiest.
    const framed = (body: JSX.Element): JSX.Element =>
        props.caption === undefined ? (
            body
        ) : props.bare === true ? (
            <div class={props.class}>
                {props.caption}
                {body}
            </div>
        ) : (
            <Card class={props.class}>
                {props.caption}
                {body}
            </Card>
        );

    return (
        <Show when={!props.isError} fallback={framed(<ErrorBox error={props.error} />)}>
            <Show
                when={!isFirstLoad()}
                fallback={tableShell(() => skeletonBody(props.skeletonRows ?? 8))}
            >
                <Show
                    when={visibleRows()}
                    fallback={framed(
                        <EmptyState title={props.emptyTitle} message={props.emptyMessage} />,
                    )}
                >
                    {(rows) =>
                        // The thunk's reads are realized inside the tracked {body()}
                        // scope in tableShell; reactivity is covered by DataTable.test.tsx.
                         
                        tableShell(() => realBody(rows()))
                    }
                </Show>
            </Show>
        </Show>
    );
}
