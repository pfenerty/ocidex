import { Show } from "solid-js";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import { Button, Card } from "~/components/ui";

/**
 * WebhookSecretBanner shows a newly minted webhook secret. The server never
 * returns it again, so this is the only chance to copy it — hence the explicit
 * dismiss rather than an auto-hiding toast.
 */
export function WebhookSecretBanner(props: { secret: string | null; onDismiss: () => void }) {
    const toast = useToast();
    return (
        <Show when={props.secret}>
            <Card tone="success" class="mb-4">
                <p class="mb-2">
                    <strong>Webhook secret.</strong> Copy it now — it will not be shown again.
                </p>
                <code class="mb-2 block break-all">
                    {props.secret}
                </code>
                <div class="flex gap-2">
                    <Button variant="primary" onClick={() => {
                        void copyText(props.secret ?? "").then(() => {
                            toast("Copied to clipboard", "success");
                        });
                    }}>
                        Copy
                    </Button>
                    <Button onClick={() => props.onDismiss()}>
                        Dismiss
                    </Button>
                </div>
            </Card>
        </Show>
    );
}
