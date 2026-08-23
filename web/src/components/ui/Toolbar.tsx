import type { JSX } from "solid-js";
import { For, Show, createEffect, createSignal, onCleanup, untrack } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import { Button } from "./Button";

/** A `<select>` choice. A bare string is shorthand for `{value: s, label: s}`. */
export type ToolbarOption = string | { value: string; label: string };

const optValue = (o: ToolbarOption): string => (typeof o === "string" ? o : o.value);
const optLabel = (o: ToolbarOption): string => (typeof o === "string" ? o : o.label);

/** The URL value a checked checkbox writes. Unchecked drops the param entirely. */
const CHECKED = "1";

export type ToolbarField =
    | { kind: "text"; key: string; placeholder?: string; label?: string }
    | {
          kind: "select";
          key: string;
          options: readonly ToolbarOption[];
          /** Label for the empty choice. Default "All". */
          allLabel?: string;
          label?: string;
      }
    | { kind: "checkbox"; key: string; label: string };

/**
 * Toolbar is the one filter row for list pages. It replaces four different
 * idioms (see ocidex-ag4q.14) with the best behaviour already in the tree:
 * 300ms-debounced text inputs from Artifacts, a Clear action from Components,
 * and URL persistence for every field so a filtered view survives reload and is
 * shareable.
 *
 * **All state lives in `useSearchParams`** — the toolbar holds no filter state
 * of its own beyond the in-flight keystroke draft. A cleared field drops its
 * param rather than writing an empty one, so "absent" is the single
 * representation of "not filtering" and URLs stay short.
 *
 * The debounce delays the *URL write*, never the input's displayed value: a
 * local draft drives the box, so typing is never laggy or reordered. Enter
 * flushes the pending write immediately rather than waiting out the timer.
 *
 * Out of scope, deliberately: the Vulnerabilities page's "Jump to CVE id" form
 * is navigation, not filtering — it routes to a detail page instead of narrowing
 * a list — so it does not belong here even though it currently shares the
 * `.search-bar` class.
 *
 * No new CSS: this emits `.search-bar`, which `index.css` already styles
 * (including the 768px wrap rule).
 */
export function Toolbar(props: {
    fields: readonly ToolbarField[];
    /** Debounce for text fields, in ms. Default 300. */
    debounceMs?: number;
    /**
     * Fired after every committed change with the full field set, so callers can
     * reset paging. Values are read straight from the URL; an inactive field is
     * the empty string.
     */
    onChange?: (values: Record<string, string>) => void;
    class?: string;
}): JSX.Element {
    const [searchParams, setSearchParams] = useSearchParams();

    const param = (key: string): string => {
        const v = searchParams[key];
        return (Array.isArray(v) ? v[0] : v) ?? "";
    };

    const [draft, setDraft] = createSignal<Record<string, string>>({});
    const timers = new Map<string, ReturnType<typeof setTimeout>>();
    onCleanup(() => {
        for (const t of timers.values()) clearTimeout(t);
    });

    // Seed the drafts from the URL, and resync whenever the URL changes from
    // outside the toolbar: a back-button navigation, a link into a pre-filtered
    // view, or Clear. A field with a timer in flight is skipped so this never
    // races the debounce and yanks characters back out from under the cursor.
    createEffect(() => {
        const current = untrack(draft);
        const next: Record<string, string> = {};
        for (const f of props.fields) {
            if (f.kind !== "text") continue;
            next[f.key] = timers.has(f.key) ? (current[f.key] ?? "") : param(f.key);
        }
        setDraft(next);
    });

    /** The full field set, with `override` applied — `setSearchParams` is a
     *  navigation and is not guaranteed to have landed when we report. */
    function values(overrideKey?: string, overrideValue?: string): Record<string, string> {
        const out: Record<string, string> = {};
        for (const f of props.fields) {
            out[f.key] = f.key === overrideKey ? (overrideValue ?? "") : param(f.key);
        }
        return out;
    }

    function commit(key: string, value: string): void {
        setSearchParams({ [key]: value === "" ? undefined : value });
        props.onChange?.(values(key, value));
    }

    function handleText(key: string, value: string): void {
        setDraft((d) => ({ ...d, [key]: value }));
        const existing = timers.get(key);
        if (existing !== undefined) clearTimeout(existing);
        timers.set(
            key,
            setTimeout(() => {
                timers.delete(key);
                commit(key, value);
            }, props.debounceMs ?? 300),
        );
    }

    /** Commit every pending keystroke now. Bound to Enter. */
    function flush(): void {
        const pending = [...timers.keys()];
        for (const t of timers.values()) clearTimeout(t);
        timers.clear();
        for (const key of pending) commit(key, draft()[key] ?? "");
    }

    // A pending draft counts as active: hiding Clear while there is visible text
    // in a box would read as the button being broken.
    const isActive = (): boolean =>
        props.fields.some((f) => param(f.key) !== "" || (draft()[f.key] ?? "") !== "");

    function clear(): void {
        for (const t of timers.values()) clearTimeout(t);
        timers.clear();
        const patch: Record<string, undefined> = {};
        for (const f of props.fields) patch[f.key] = undefined;
        setSearchParams(patch);
        setDraft({});
        props.onChange?.(Object.fromEntries(props.fields.map((f) => [f.key, ""])));
    }

    function renderField(f: ToolbarField): JSX.Element {
        if (f.kind === "text") {
            return (
                <input
                    type="text"
                    aria-label={f.label ?? f.placeholder ?? "Filter"}
                    placeholder={f.placeholder}
                    value={draft()[f.key] ?? ""}
                    onInput={(e) => handleText(f.key, e.currentTarget.value)}
                />
            );
        }
        if (f.kind === "select") {
            return (
                <select
                    aria-label={f.label ?? f.allLabel ?? "Filter"}
                    value={param(f.key)}
                    onChange={(e) => commit(f.key, e.currentTarget.value)}
                >
                    <option value="">{f.allLabel ?? "All"}</option>
                    <For each={f.options}>
                        {(o) => <option value={optValue(o)}>{optLabel(o)}</option>}
                    </For>
                </select>
            );
        }
        return (
            <label class="toolbar-check">
                <input
                    type="checkbox"
                    checked={param(f.key) === CHECKED}
                    onChange={(e) => commit(f.key, e.currentTarget.checked ? CHECKED : "")}
                />
                {f.label}
            </label>
        );
    }

    return (
        <form
            class={props.class !== undefined ? `search-bar ${props.class}` : "search-bar"}
            onSubmit={(e) => {
                e.preventDefault();
                flush();
            }}
        >
            <For each={props.fields}>{(f) => renderField(f)}</For>
            <Show when={isActive()}>
                <Button type="button" size="sm" onClick={clear}>
                    Clear
                </Button>
            </Show>
        </form>
    );
}
