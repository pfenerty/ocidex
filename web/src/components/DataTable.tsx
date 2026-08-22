import "./DataTable.css";
import { Show, For, createSignal, createMemo, createEffect } from "solid-js";
import type { JSX } from "solid-js";
import { ErrorBox, EmptyState } from "~/components/Feedback";
import { Skeleton } from "~/components/Skeleton";
import Pagination from "~/components/Pagination";
import LoadMore from "~/components/LoadMore";
import type { PaginationMeta } from "~/api/client";

export type SortDir = "asc" | "desc";

export interface Column<T> {
    header: string;
    sortKey?: string;
    /** Default sort direction when this column becomes active. Default "text". */
    sortType?: "text" | "numeric";
    /** Required for client-side sort mode (when onSort is not provided). */
    sortValue?: (row: T) => string | number;
    align?: "left" | "right";
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
    emptyMessage?: string;
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
                            <td class={col.align === "right" ? "text-right" : ""}>
                                <Skeleton height="0.85em" />
                            </td>
                        )}
                    </For>
                </tr>
            )}
        </For>
    );

    const realBody = (rows: T[]) => (
        <For each={rows}>
            {(row) => (
                <tr>
                    <For each={props.columns}>
                        {(col) => (
                            <td class={col.align === "right" ? "text-right" : ""}>
                                {col.render(row)}
                            </td>
                        )}
                    </For>
                </tr>
            )}
        </For>
    );

    // body is a thunk so the tbody stays reactive: reading rows()/isRefetching()
    // inside the {body()} expression lets Solid re-render just the tbody on
    // pagination, sort, and refetch without rebuilding the card/headers.
    const tableShell = (body: () => JSX.Element) => (
        // aria-busy rather than a swap to shimmer: a refetch on this table is
        // almost always a sort, a page, or a keystroke in a debounced filter,
        // and blanking the rows the reader is mid-sentence in loses their place
        // to announce something they already know they asked for. The rows stay
        // put and dim; a screen reader gets the busy state it would otherwise
        // have to infer from the content vanishing.
        <div class="card" classList={{ "table-refetching": isRefetching() }} aria-busy={isRefetching()}>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <For each={props.columns}>
                                {(col) => (
                                    <th
                                        class={
                                            (col.sortKey !== undefined ? "th-sortable " : "") +
                                            (col.align === "right" ? "text-right" : "")
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
        </div>
    );

    return (
        <Show when={!props.isError} fallback={<ErrorBox error={props.error} />}>
            <Show
                when={!isFirstLoad()}
                fallback={tableShell(() => skeletonBody(props.skeletonRows ?? 8))}
            >
                <Show
                    when={visibleRows()}
                    fallback={<EmptyState title={props.emptyTitle} message={props.emptyMessage} />}
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
