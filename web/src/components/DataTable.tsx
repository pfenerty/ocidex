import "./DataTable.css";
import { Show, For, createSignal, createMemo, createEffect } from "solid-js";
import type { JSX } from "solid-js";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
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

    return (
        <Show when={!isFirstLoad()} fallback={<Loading />}>
            <Show when={!props.isError} fallback={<ErrorBox error={props.error} />}>
                <Show
                    when={visibleRows()}
                    fallback={<EmptyState title={props.emptyTitle} message={props.emptyMessage} />}
                >
                    {(rows) => (
                        <div class="card">
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
                                    <tbody>
                                        <Show
                                            when={!isRefetching()}
                                            fallback={
                                                <For each={rows()}>
                                                    {() => (
                                                        <tr>
                                                            <For each={props.columns}>
                                                                {(col) => (
                                                                    <td class={col.align === "right" ? "text-right" : ""}>
                                                                        <span class="skeleton-cell" />
                                                                    </td>
                                                                )}
                                                            </For>
                                                        </tr>
                                                    )}
                                                </For>
                                            }
                                        >
                                            <For each={rows()}>
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
                                        </Show>
                                    </tbody>
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
                    )}
                </Show>
            </Show>
        </Show>
    );
}
