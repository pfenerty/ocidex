import { Show } from "solid-js";
import "./Pagination.css";
import { Button } from "~/components/ui";

/**
 * Footer for keyset (cursor) paginated lists — ADR-043's rules 2 and 3.
 *
 * Deliberately the same shape as <Pagination>: the same `.pagination` row, a
 * count on the left, controls on the right. The two used to look like different
 * components rather than two settings of one, because this one centred a lone
 * button and said nothing about how much of the list you were looking at.
 *
 * It also rendered *nothing* once `hasMore` went false, so reaching the end of
 * a list made the footer vanish and the page jump. The count line stays either
 * way — arriving at the end of a list is information, not an absence.
 *
 * A keyset response carries no total (CursorMeta is `hasMore`/`nextCursor`/
 * `limit`), so the count reports what is loaded and says nothing it cannot
 * know: "Showing 40" while more remain, "Showing 40 of 40" once they do not.
 */
export default function LoadMore(props: {
    hasMore: boolean;
    loading: boolean;
    onClick: () => void;
    /** How many rows are on screen. */
    loaded?: number;
}) {
    const label = (): string => {
        const n = props.loaded;
        if (n === undefined) return "";
        if (n === 0) return "No results";
        return props.hasMore ? `Showing ${n}` : `Showing ${n} of ${n}`;
    };

    return (
        <div class="pagination">
            <span>{label()}</span>
            <div class="pagination-controls">
                <Show when={props.hasMore}>
                    <Button size="sm" loading={props.loading} onClick={() => props.onClick()}>
                        {props.loading ? "Loading…" : "Load more"}
                    </Button>
                </Show>
            </div>
        </div>
    );
}
