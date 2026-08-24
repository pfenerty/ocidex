import "./Pagination.css";
import type { PaginationMeta } from "~/api/client";
import { Button } from "~/components/ui";

interface PaginationProps {
    pagination: PaginationMeta;
    onPageChange: (offset: number) => void;
}

export default function Pagination(props: PaginationProps) {
    const totalPages = () =>
        Math.max(1, Math.ceil(props.pagination.total / props.pagination.limit));

    const currentPage = () =>
        Math.floor(props.pagination.offset / props.pagination.limit) + 1;

    const hasPrev = () => props.pagination.offset > 0;

    const hasNext = () =>
        props.pagination.offset + props.pagination.limit <
        props.pagination.total;

    const goTo = (page: number) => {
        props.onPageChange((page - 1) * props.pagination.limit);
    };

    return (
        <div class="pagination">
            <span>
                {props.pagination.total === 0
                    ? "No results"
                    : `Showing ${props.pagination.offset + 1}–${Math.min(props.pagination.offset + props.pagination.limit, props.pagination.total)} of ${props.pagination.total}`}
            </span>
            <div class="pagination-controls">
                <Button size="sm" aria-label="First page" disabled={!hasPrev()} onClick={() => goTo(1)}>
                    ««
                </Button>
                <Button
                    size="sm"
                    aria-label="Previous page"
                    disabled={!hasPrev()}
                    onClick={() => goTo(currentPage() - 1)}
                >
                    «
                </Button>
                <span>
                    {currentPage()} / {totalPages()}
                </span>
                <Button
                    size="sm"
                    aria-label="Next page"
                    disabled={!hasNext()}
                    onClick={() => goTo(currentPage() + 1)}
                >
                    »
                </Button>
                <Button
                    size="sm"
                    aria-label="Last page"
                    disabled={!hasNext()}
                    onClick={() => goTo(totalPages())}
                >
                    »»
                </Button>
            </div>
        </div>
    );
}
