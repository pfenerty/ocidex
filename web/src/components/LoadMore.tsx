import { Show } from "solid-js";
import "./Pagination.css";
import { Button } from "~/components/ui";

/** Load-more button for keyset (cursor) paginated lists. Renders nothing when
 *  there are no further pages. */
export default function LoadMore(props: {
    hasMore: boolean;
    loading: boolean;
    onClick: () => void;
}) {
    return (
        <Show when={props.hasMore}>
            <div class="pagination" style={{ "justify-content": "center" }}>
                <Button loading={props.loading} onClick={() => props.onClick()}>
                    {props.loading ? "Loading…" : "Load more"}
                </Button>
            </div>
        </Show>
    );
}
