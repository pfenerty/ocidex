import { createContext, useContext, createSignal, For, type ParentProps } from "solid-js";

type ToastType = "success" | "error" | "info";

interface Toast {
    id: number;
    message: string;
    type: ToastType;
}

interface ToastContextValue {
    toast: (message: string, type?: ToastType) => void;
}

const ToastContext = createContext<ToastContextValue>();

const DURATION_MS = 3000;

export function ToastProvider(props: ParentProps) {
    const [toasts, setToasts] = createSignal<Toast[]>([]);
    let nextId = 0;

    function toast(message: string, type: ToastType = "info") {
        const id = nextId++;
        setToasts((prev) => [...prev, { id, message, type }]);
        setTimeout(() => {
            setToasts((prev) => prev.filter((t) => t.id !== id));
        }, DURATION_MS);
    }

    return (
        <ToastContext.Provider value={{ toast }}>
            {props.children}
            <div class="toast-container">
                <For each={toasts()}>
                    {(t) => <div class={`toast toast--${t.type}`}>{t.message}</div>}
                </For>
            </div>
        </ToastContext.Provider>
    );
}

export function useToast() {
    const ctx = useContext(ToastContext);
    if (!ctx) throw new Error("useToast must be used inside ToastProvider");
    return ctx.toast;
}
