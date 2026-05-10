import { createSignal } from "solid-js";

export function createLocalStorageSignal<T>(
    key: string,
    defaultValue: T,
): [() => T, (value: T) => void] {
    const stored = localStorage.getItem(key);
    let initial: T = defaultValue;
    if (stored !== null) {
        try {
            initial = JSON.parse(stored) as T;
        } catch {
            // corrupt entry — fall back to default
        }
    }
    const [value, setInner] = createSignal<T>(initial);
    return [
        value,
        (v: T) => {
            setInner(() => v);
            localStorage.setItem(key, JSON.stringify(v));
        },
    ];
}
