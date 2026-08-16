import { Show } from "solid-js";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";

/**
 * WebhookSecretBanner shows a newly minted webhook secret. The server never
 * returns it again, so this is the only chance to copy it — hence the explicit
 * dismiss rather than an auto-hiding toast.
 */
export function WebhookSecretBanner(props: { secret: string | null; onDismiss: () => void }) {
    const toast = useToast();
    return (
        <Show when={props.secret}>
            <div class="card" style={{ "border-color": "var(--color-success)", "margin-bottom": "1rem" }}>
                <p style={{ "margin-bottom": "0.5rem" }}>
                    <strong>Webhook secret.</strong> Copy it now — it will not be shown again.
                </p>
                <code style={{ "word-break": "break-all", display: "block", "margin-bottom": "0.5rem" }}>
                    {props.secret}
                </code>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button class="btn btn-primary" onClick={() => {
                        void copyText(props.secret ?? "").then(() => {
                            toast("Copied to clipboard", "success");
                        });
                    }}>
                        Copy
                    </button>
                    <button class="btn" onClick={() => props.onDismiss()}>
                        Dismiss
                    </button>
                </div>
            </div>
        </Show>
    );
}
