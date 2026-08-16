import type { Accessor, JSX } from "solid-js";
import { Show } from "solid-js";
import { ErrorBox } from "~/components/Feedback";

/**
 * QueryBoundary collapses the loading / error / empty / data ladder that every
 * detail page nested by hand, three or four `<Show>` deep. Written out, the
 * ladder is easy to get subtly wrong — the usual bug is checking `isError`
 * inside the loading branch, so a failed refetch renders a skeleton forever.
 *
 * `when` narrows "has data" beyond `!== undefined` (e.g. "has at least one
 * version"); omit it to mean any defined data.
 */
export function QueryBoundary<T>(props: {
    query: { isLoading: boolean; isError: boolean; error: unknown; data: T | undefined };
    /** Rendered while the first fetch is in flight — usually a Skeleton. */
    loading: JSX.Element;
    /** Rendered when the query resolves with nothing to show. */
    empty?: JSX.Element;
    when?: (data: NonNullable<T>) => boolean;
    children: (data: Accessor<NonNullable<T>>) => JSX.Element;
}): JSX.Element {
    const resolved = (): NonNullable<T> | undefined => {
        const d = props.query.data;
        if (d === undefined || d === null) return undefined;
        const value = d as NonNullable<T>;
        if (props.when !== undefined && !props.when(value)) return undefined;
        return value;
    };

    return (
        <Show when={!props.query.isLoading} fallback={props.loading}>
            <Show when={!props.query.isError} fallback={<ErrorBox error={props.query.error} />}>
                <Show when={resolved()} keyed fallback={props.empty}>
                    {(data) => props.children(() => data)}
                </Show>
            </Show>
        </Show>
    );
}
