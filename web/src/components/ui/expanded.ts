import { createSignal } from "solid-js";

/**
 * createExpandedSet is the "which rows are expanded" signal, shared by the job
 * tables, the component overview and the dependency tree. Each of them had its
 * own copy of the same clone-mutate-return reducer, which is the shape you must
 * use: mutating the existing Set in place would not change its identity, so
 * Solid would not re-render.
 */
export function createExpandedSet(): {
    has: (key: string) => boolean;
    toggle: (key: string) => void;
    replace: (keys: Set<string>) => void;
    clear: () => void;
} {
    const [expanded, setExpanded] = createSignal(new Set<string>());
    return {
        has: (key) => expanded().has(key),
        toggle: (key) =>
            setExpanded((prev) => {
                const next = new Set(prev);
                if (next.has(key)) next.delete(key);
                else next.add(key);
                return next;
            }),
        replace: (keys) => setExpanded(() => new Set(keys)),
        clear: () => setExpanded(() => new Set<string>()),
    };
}
