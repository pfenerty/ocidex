import type { JSX } from "solid-js";

/**
 * Modal wraps a native `<dialog>`. Control is deliberately imperative — the
 * caller keeps the element and calls `showModal()` / `close()` on it — because
 * that is what the browser's top-layer and focus-trap behaviour is built
 * around, and a boolean `open` prop would have to re-implement both.
 *
 * `onClose` fires for every dismissal route, including Escape, which is the
 * case a hand-rolled dialog usually forgets to reset state for.
 */
export function Modal(props: {
    ref: (el: HTMLDialogElement) => void;
    title: JSX.Element;
    onClose?: () => void;
    children: JSX.Element;
}): JSX.Element {
    return (
        <dialog ref={props.ref} onClose={() => props.onClose?.()}>
            <div style={{ padding: "1.5rem" }}>
                <div class="card-header">
                    <h3>{props.title}</h3>
                </div>
                {props.children}
            </div>
        </dialog>
    );
}
