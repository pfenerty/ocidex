import "./ClusterDetail/ClusterDetail.css";
import { Show } from "solid-js";
import { Button, Card, Modal } from "~/components/ui";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import type { Cluster } from "~/api/client";

export const UNINSTALL_COMMAND = "helm uninstall ocidex-k8s-agent -n ocidex-agent";

/**
 * RetireClusterDialog replaces a native confirm() that said only "its
 * inventory goes with it" (ocidex-70eo.9, audit E2). Retiring a cluster has
 * two answers with different costs, and the reader should choose between them
 * knowing what each one keeps.
 */
export function RetireClusterDialog(props: {
    ref: (el: HTMLDialogElement) => void;
    cluster: Cluster | null;
    busy: boolean;
    onPause: (c: Cluster) => void;
    onDelete: (c: Cluster) => void;
    onCancel: () => void;
}) {
    const toast = useToast();
    return (
        <Modal ref={props.ref} title={`Retire ${props.cluster?.name ?? "cluster"}`} size="sm">
            <Show when={props.cluster}>
                {(c) => (
                    <div class="grid grid-cols-[minmax(0,1fr)] gap-4" data-testid="retire-dialog">
                        <div>
                            <p class="mb-2">
                                First, remove the agent from the cluster so it stops pushing:
                            </p>
                            <pre class="agent-setup-commands">{UNINSTALL_COMMAND}</pre>
                            <Button
                                size="sm"
                                onClick={() => {
                                    void copyText(UNINSTALL_COMMAND).then(() =>
                                        toast("Copied to clipboard", "success"),
                                    );
                                }}
                            >
                                Copy
                            </Button>
                        </div>

                        <Show when={c().pausedAt === undefined}>
                            <Card>
                                <strong>Pause</strong>
                                <p class="text-muted mb-2">
                                    Keeps everything: the last inventory stays readable, the images
                                    it lists stay protected from retention, and credentials keep
                                    their keys. Any push is refused until you resume.
                                </p>
                                <Button disabled={props.busy} onClick={() => props.onPause(c())}>
                                    Pause cluster
                                </Button>
                            </Card>
                        </Show>

                        <Card>
                            <strong>Delete</strong>
                            <ul class="text-muted mb-2 list-disc pl-5">
                                <li>Its reported inventory is deleted.</li>
                                <li>Its agent credentials are revoked.</li>
                                <li>
                                    SBOMs it ingested stay, but no longer record that they came from
                                    this cluster.
                                </li>
                                <li>
                                    Images that run only here lose their protection from retention.
                                </li>
                            </ul>
                            <Button
                                variant="danger"
                                disabled={props.busy}
                                onClick={() => props.onDelete(c())}
                            >
                                Delete {c().name}
                            </Button>
                        </Card>

                        <div>
                            <Button onClick={() => props.onCancel()}>Cancel</Button>
                        </div>
                    </div>
                )}
            </Show>
        </Modal>
    );
}
