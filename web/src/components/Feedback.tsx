import { Show } from "solid-js";
import type { Accessor, JSX } from "solid-js";
import { APIClientError } from "~/api/client";

export function Loading(props: { message?: string }): JSX.Element {
    return (
        <div class="loading">
            <div class="spinner" />
            {props.message ?? "Loading…"}
        </div>
    );
}

export function ErrorBox(props: { error: unknown }): JSX.Element {
    const info = () => {
        const e = props.error;
        if (e instanceof APIClientError) {
            const body = e.body as
                | { title?: string; detail?: string; status?: number }
                | null
                | undefined;
            const title = body?.title ?? `Error ${e.status}`;
            const detail = body?.detail;
            return { title, detail };
        }
        if (e instanceof Error) {
            return { title: e.message, detail: undefined };
        }
        if (typeof e === "string") {
            return { title: e, detail: undefined };
        }
        return { title: "An unexpected error occurred", detail: undefined };
    };

    return (
        <div class="error-box">
            <strong>{info().title}</strong>
            <Show when={info().detail}>
                <p>{info().detail}</p>
            </Show>
        </div>
    );
}

export function EmptyState(props: {
    title: string;
    message?: string;
}): JSX.Element {
    return (
        <div class="empty-state">
            <strong>{props.title}</strong>
            {props.message !== undefined && <p>{props.message}</p>}
        </div>
    );
}

export function QueryResult<T>(props: {
    query: {
        isLoading: boolean;
        isError: boolean;
        error: unknown;
        data: T | undefined;
    };
    when: (data: T) => T | null | undefined | false;
    empty?: JSX.Element;
    children: (data: Accessor<NonNullable<T>>) => JSX.Element;
}): JSX.Element {
    const resolved = () => {
        const d = props.query.data;
        if (d === undefined) return undefined;
        const w = props.when(d);
        return w !== null && w !== undefined && w !== false ? (w as NonNullable<T>) : undefined;
    };
    return (
        <Show when={!props.query.isLoading} fallback={<Loading />}>
            <Show
                when={!props.query.isError}
                fallback={<ErrorBox error={props.query.error} />}
            >
                <Show when={resolved()} fallback={props.empty}>
                    {props.children}
                </Show>
            </Show>
        </Show>
    );
}
