import { Show, createMemo, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import { Button, Card, CardHeader, Segmented } from "~/components/ui";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import { useCreateClusterCredential, useListNamespaces } from "~/api/queries";
import { helmInstallCommand, installKeyFor, rememberInstallKey, valuesYaml } from "./installKey";

type Form = "helm" | "values";

/**
 * InstallAgent is steps two and three of connecting a cluster (ocidex-70eo.6):
 * one command to run against it, then a live wait for the first snapshot. It
 * is the whole page until the cluster reports; the cluster query polls every
 * 5s meanwhile, so this card replaces itself with the inventory on its own.
 *
 * The key comes from the connect page, in memory. Arriving any other way
 * (a reload, a link) there is no key to show, since it was shown once, so the
 * card offers to mint a fresh credential instead.
 */
export function InstallAgent(props: {
    clusterId: string;
    clusterName: string;
    namespaceId: string | undefined;
    health: { state: string; reason?: string } | undefined;
}) {
    const toast = useToast();
    const namespaces = useListNamespaces();
    const create = useCreateClusterCredential();
    const [form, setForm] = createSignal<Form>("helm");

    const canMint = createMemo(() => {
        const caps = (namespaces.data?.data ?? []).find((n) => n.id === props.namespaceId)?.capabilities ?? [];
        return caps.includes("manage_cluster") && caps.includes("push_inventory");
    });
    const install = () => installKeyFor(props.clusterId);
    const [serverUrl, setServerUrl] = createSignal<string | undefined>(undefined);
    // The configured public API URL wins over the page's own origin, which is
    // wrong whenever API_BASE_URL differs from the web host (audit D7).
    const effectiveServerUrl = () => serverUrl() ?? install()?.serverUrl ?? window.location.origin;

    const command = () => {
        const k = install();
        if (k === undefined) return "";
        return form() === "helm"
            ? helmInstallCommand({ serverUrl: effectiveServerUrl(), clusterId: props.clusterId, key: k.key })
            : valuesYaml({ serverUrl: effectiveServerUrl(), clusterId: props.clusterId });
    };

    function mint() {
        create.mutate(
            { id: props.clusterId },
            {
                onSuccess: (d) => {
                    if (d.key !== undefined) rememberInstallKey(props.clusterId, { key: d.key, serverUrl: d.serverUrl });
                },
                onError: () => toast("Failed to create a credential", "error"),
            },
        );
    }

    return (
        <div class="grid gap-4" data-testid="install-agent">
            <div class="connect-steps">
                <span class="done">1 Named</span>
                <span class={props.health?.state === "erroring" ? "done" : "now"}>2 Install the agent</span>
                <span class={props.health?.state === "erroring" ? "now" : ""}>3 First snapshot</span>
            </div>

            <Card>
                <CardHeader
                    title={install() !== undefined ? "Install the agent" : `Finish connecting ${props.clusterName}`}
                    actions={
                        <Show when={install()}>
                            <Segmented
                                label="Install format"
                                options={[
                                    { id: "helm", label: "helm" },
                                    { id: "values", label: "values.yaml" },
                                ]}
                                value={form()}
                                onChange={setForm}
                            />
                        </Show>
                    }
                />
                <p>
                    <strong>{props.clusterName}</strong> is registered, but no agent has reported. Until one
                    does, OCIDex knows nothing about what runs here, which is not the same as knowing that
                    nothing runs.
                </p>
                <Show
                    when={install()}
                    fallback={
                        <Show
                            when={canMint()}
                            fallback={
                                <p class="text-muted">
                                    The install command carries a key that was shown once. Ask someone who can
                                    manage this cluster for a new one, or install with your own{" "}
                                    <A
                                        class="dash-link"
                                        href={`/admin/keys?${new URLSearchParams({
                                            name: `${props.clusterName}-agent`,
                                            capabilities: "push_inventory",
                                        }).toString()}`}
                                    >
                                        API key with push_inventory
                                    </A>
                                    .
                                </p>
                            }
                        >
                            <p class="text-muted">
                                The install command carries a key that was shown once. Get a new command; this
                                mints a fresh credential, and the old one keeps working until you revoke it.
                            </p>
                            <div>
                                <Button variant="primary" disabled={create.isPending} onClick={mint}>
                                    {create.isPending ? "Creating…" : "Get install command"}
                                </Button>
                            </div>
                        </Show>
                    }
                >
                    <pre class="agent-setup-commands">{command()}</pre>
                    <div class="flex flex-wrap items-center justify-between gap-2">
                        <span class="text-muted text-sm">
                            {form() === "helm"
                                ? "This is the only time the key is shown. Lost it? Get a new one from Agent credentials."
                                : "Commit this file; keep the key in the Secret it names, never in Git."}
                        </span>
                        <Button
                            variant="primary"
                            onClick={() => {
                                void copyText(command()).then(() => toast("Copied to clipboard", "success"));
                            }}
                        >
                            Copy
                        </Button>
                    </div>
                    <label class="mt-3 grid gap-1 text-sm">
                        <span>
                            server.url <span class="text-muted">must be reachable from inside the target cluster</span>
                        </span>
                        <input
                            id="install-server-url"
                            type="text"
                            class="font-mono"
                            value={effectiveServerUrl()}
                            onInput={(e) => setServerUrl(e.currentTarget.value)}
                        />
                    </label>
                </Show>
            </Card>

            <Show
                when={props.health?.state === "erroring"}
                fallback={
                    <Card>
                        <span class="connect-wait">
                            <span class="connect-spinner" aria-hidden="true" />
                            <span>
                                <strong>Waiting for the first snapshot.</strong> This updates by itself once the
                                agent reports.
                            </span>
                        </span>
                    </Card>
                }
            >
                <Card tone="danger" data-testid="install-erroring">
                    <strong>The agent is reporting, and OCIDex is refusing it.</strong>
                    <p class="mb-0">{props.health?.reason}</p>
                </Card>
            </Show>
        </div>
    );
}
