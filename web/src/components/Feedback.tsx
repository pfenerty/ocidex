import { Show } from "solid-js";
import type { JSX } from "solid-js";
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
            {props.message && <p>{props.message}</p>}
        </div>
    );
}
