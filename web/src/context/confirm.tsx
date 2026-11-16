import "./confirm.css";
import { createContext, createSignal, useContext, type JSX, type ParentProps } from "solid-js";
import { Button, Modal } from "~/components/ui";

export interface ConfirmOptions {
    /** The question, naming the object: `Delete namespace "team-a"?` */
    title: string;
    /** What happens and what it costs. */
    body: JSX.Element;
    /** The verb on the button: "Delete", "Revoke", "Re-scan" — never "OK". */
    confirmLabel: string;
    /** `danger` (default) for anything destructive; `default` for heavy-but-safe. */
    tone?: "danger" | "default";
}

export type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn>();

/**
 * One confirmation dialog for every destructive action (ocidex-iz0r.7).
 *
 * The app had three patterns: native `window.confirm()` at six sites, a styled
 * Modal at two, and nothing at all on API key delete, registry delete and
 * account unlink. A native confirm can't name its button, can't be themed,
 * and blocks the event loop; none of it can say what the action will cost.
 * This is the one shape: a question that names the object, a body that says
 * what goes with it, and a button labelled with the verb.
 */
export function ConfirmProvider(props: ParentProps) {
    let dialog: HTMLDialogElement | undefined;
    const [options, setOptions] = createSignal<ConfirmOptions | null>(null);
    let resolve: ((ok: boolean) => void) | null = null;

    // Every dismissal route ends here: the buttons, Escape and a second
    // confirm() opening over the first. `onClose` fires after our own close()
    // too, which finds `resolve` already cleared and does nothing.
    function settle(ok: boolean) {
        const r = resolve;
        resolve = null;
        if (dialog?.open === true) dialog.close();
        r?.(ok);
    }

    const confirm: ConfirmFn = (next) => {
        settle(false);
        setOptions(next);
        return new Promise<boolean>((res) => {
            resolve = res;
            dialog?.showModal();
        });
    };

    return (
        <ConfirmContext.Provider value={confirm}>
            {props.children}
            <Modal
                ref={(el) => (dialog = el)}
                title={options()?.title ?? ""}
                size="sm"
                onClose={() => settle(false)}
            >
                <div class="confirm-body">{options()?.body}</div>
                <div class="confirm-actions">
                    <Button onClick={() => settle(false)}>Cancel</Button>
                    <Button
                        variant={options()?.tone === "default" ? "primary" : "danger"}
                        class="confirm-go"
                        onClick={() => settle(true)}
                    >
                        {options()?.confirmLabel}
                    </Button>
                </div>
            </Modal>
        </ConfirmContext.Provider>
    );
}

export function useConfirm(): ConfirmFn {
    const ctx = useContext(ConfirmContext);
    if (!ctx) throw new Error("useConfirm must be used inside ConfirmProvider");
    return ctx;
}
