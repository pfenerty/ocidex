import type { JSX } from "solid-js";
import { For, Show, createMemo, createSignal, createUniqueId } from "solid-js";
import "./Combobox.css";

/**
 * A type-to-filter picker over an in-memory list.
 *
 * This exists because Compare (`pages/Diff.tsx`) asked a reader to find two
 * SBOMs inside four native `<select>`s. A `<select>` is a fine control for six
 * options and an unscannable wall for two hundred — you cannot see what you are
 * looking for, and you cannot type your way to it beyond the browser's
 * first-letter jump. That is the main reason Compare went unused
 * (ocidex-ag4q.41).
 *
 * **The filter is synchronous and undebounced, on purpose.** The Toolbar
 * primitive debounces because each keystroke there becomes a URL write and a
 * refetch; here the candidates are already in memory, so a debounce would only
 * add lag between the keystroke and the list narrowing. What is borrowed from
 * Toolbar is the *shape* — one text box, results that narrow as you type, a
 * visible way back out — not its search-param state model, which does not fit a
 * control whose selection is a component-local signal.
 *
 * The input shows the *selected* item's label when closed and the query while
 * open, so the control reads as a picker at rest and as a search box in use.
 * Escape restores the closed state without changing the selection.
 *
 * Matching is case-insensitive, and every whitespace-separated term must appear
 * somewhere in the label or sub-label — so "svc 1.1" finds an entry regardless
 * of the order those two strings appear in.
 */
export function Combobox<T>(props: {
    items: readonly T[];
    /** The selected item's id, or "" for no selection. */
    value: string;
    onSelect: (id: string) => void;
    itemId: (item: T) => string;
    itemLabel: (item: T) => string;
    /** Secondary line, also searched. */
    itemSub?: (item: T) => string | undefined;
    placeholder?: string;
    /** Accessible name. Required — the control has no visible <label>. */
    label: string;
    disabled?: boolean;
    /** Shown when the query matches nothing. Default "No matches". */
    emptyMessage?: string;
    class?: string;
}): JSX.Element {
    const listId = createUniqueId();
    const [query, setQuery] = createSignal("");
    const [open, setOpen] = createSignal(false);
    const [highlight, setHighlight] = createSignal(0);

    const selected = createMemo(() => props.items.find((i) => props.itemId(i) === props.value));

    const haystack = (item: T): string =>
        `${props.itemLabel(item)} ${props.itemSub?.(item) ?? ""}`.toLowerCase();

    const matches = createMemo(() => {
        const terms = query().toLowerCase().split(/\s+/).filter((t) => t !== "");
        if (terms.length === 0) return props.items;
        return props.items.filter((item) => {
            const hay = haystack(item);
            return terms.every((t) => hay.includes(t));
        });
    });

    /** What the box displays: the query while searching, the selection at rest. */
    const displayed = (): string => {
        if (open()) return query();
        const sel = selected();
        return sel !== undefined ? props.itemLabel(sel) : "";
    };

    function openWith(q: string): void {
        setQuery(q);
        setOpen(true);
        setHighlight(0);
    }

    function choose(item: T): void {
        props.onSelect(props.itemId(item));
        setOpen(false);
        setQuery("");
    }

    function onKeyDown(e: KeyboardEvent): void {
        const list = matches();
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            if (!open()) {
                openWith("");
                return;
            }
            if (list.length === 0) return;
            const step = e.key === "ArrowDown" ? 1 : -1;
            setHighlight((h) => (h + step + list.length) % list.length);
            return;
        }
        if (e.key === "Enter") {
            if (!open()) return;
            e.preventDefault();
            const item = list[highlight()];
            if (item !== undefined) choose(item);
            return;
        }
        if (e.key === "Escape") {
            setOpen(false);
            setQuery("");
        }
    }

    return (
        <div
            class={props.class !== undefined ? `combobox ${props.class}` : "combobox"}
            // Closing on focusout rather than on blur so a click that lands on
            // an option does not close the list out from under the click.
            onFocusOut={(e) => {
                const next = e.relatedTarget;
                if (next instanceof Node && e.currentTarget.contains(next)) return;
                setOpen(false);
                setQuery("");
            }}
        >
            <input
                type="text"
                role="combobox"
                aria-label={props.label}
                aria-expanded={open()}
                aria-controls={listId}
                aria-autocomplete="list"
                autocomplete="off"
                placeholder={props.placeholder}
                disabled={props.disabled === true}
                value={displayed()}
                onInput={(e) => openWith(e.currentTarget.value)}
                onFocus={() => openWith("")}
                onKeyDown={onKeyDown}
            />
            <Show when={props.value !== "" && props.disabled !== true}>
                <button
                    type="button"
                    class="combobox-clear"
                    aria-label={`Clear ${props.label}`}
                    onClick={() => {
                        props.onSelect("");
                        setQuery("");
                    }}
                >
                    ×
                </button>
            </Show>
            <Show when={open()}>
                <ul class="combobox-list" id={listId} role="listbox" aria-label={props.label}>
                    <Show
                        when={matches().length > 0}
                        fallback={
                            <li class="combobox-empty">{props.emptyMessage ?? "No matches"}</li>
                        }
                    >
                        <For each={matches()}>
                            {(item, i) => (
                                <li
                                    role="option"
                                    aria-selected={props.itemId(item) === props.value}
                                    class={i() === highlight() ? "combobox-option is-active" : "combobox-option"}
                                    onMouseEnter={() => setHighlight(i())}
                                    // mousedown, not click: click fires after
                                    // focusout, by which point the list is gone.
                                    onMouseDown={(e) => {
                                        e.preventDefault();
                                        choose(item);
                                    }}
                                >
                                    <span class="combobox-option-label">{props.itemLabel(item)}</span>
                                    <Show when={props.itemSub?.(item)}>
                                        {(sub) => <span class="combobox-option-sub">{sub()}</span>}
                                    </Show>
                                </li>
                            )}
                        </For>
                    </Show>
                </ul>
            </Show>
        </div>
    );
}
