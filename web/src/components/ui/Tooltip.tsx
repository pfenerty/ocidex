import { createSignal, createUniqueId, onCleanup, Show } from "solid-js";
import type { JSX } from "solid-js";
import { Portal } from "solid-js/web";
import "./Tooltip.css";

// Gap between the trigger and the tooltip, and the space below the viewport
// top needed to render above the trigger without clipping.
const OFFSET = 6;
const FLIP_MARGIN = 64;

interface Position {
    top: number;
    left: number;
    below: boolean;
}

// Tooltip attaches an explanatory panel to an inline element, shown on hover
// and on keyboard focus.
//
// It replaces the native `title` attribute, which is unstyleable, appears after
// a browser-controlled delay, and is never shown to keyboard users at all.
//
// The panel is portalled to <body> and positioned with fixed coordinates rather
// than being absolutely positioned inside a relative wrapper. Its callers sit
// inside .table-wrapper, which scrolls on both axes, so an in-flow tooltip
// would be clipped by the very table it annotates.
export function Tooltip(props: { content: string; children: JSX.Element }) {
    const id = createUniqueId();
    const [position, setPosition] = createSignal<Position | null>(null);
    let trigger: HTMLSpanElement | undefined;

    const hide = () => setPosition(null);

    const show = () => {
        if (!trigger) return;
        const rect = trigger.getBoundingClientRect();
        // Flip below when there is not enough room above, so a badge in the
        // first table row is not pushed off the top of the screen.
        const below = rect.top < FLIP_MARGIN;
        setPosition({
            top: below ? rect.bottom + OFFSET : rect.top - OFFSET,
            left: rect.left + rect.width / 2,
            below,
        });
    };

    // The coordinates are a snapshot of where the trigger was, so any movement
    // of the page invalidates them. Dismissing is both simpler and less
    // distracting than tracking. Capture phase catches scrolling in
    // .table-wrapper, which does not bubble.
    const onScroll = () => hide();
    const onKeyDown = (e: KeyboardEvent) => {
        if (e.key === "Escape") hide();
    };
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    document.addEventListener("keydown", onKeyDown);
    onCleanup(() => {
        window.removeEventListener("scroll", onScroll, true);
        window.removeEventListener("resize", onScroll);
        document.removeEventListener("keydown", onKeyDown);
    });

    return (
        <>
            <span
                ref={trigger}
                class="tooltip-trigger"
                tabindex="0"
                aria-describedby={position() ? id : undefined}
                onMouseEnter={show}
                onMouseLeave={hide}
                onFocus={show}
                onBlur={hide}
            >
                {props.children}
            </span>
            <Show when={position()}>
                {(p) => (
                    <Portal>
                        <span
                            id={id}
                            role="tooltip"
                            class={`tooltip-content ${p().below ? "tooltip-below" : "tooltip-above"}`}
                            style={{ top: `${p().top}px`, left: `${p().left}px` }}
                        >
                            {props.content}
                        </span>
                    </Portal>
                )}
            </Show>
        </>
    );
}
