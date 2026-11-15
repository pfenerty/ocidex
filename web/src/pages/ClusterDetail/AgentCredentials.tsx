import { Show, createMemo, createSignal } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { components } from "~/types/openapi";
import { Button, Card, CardHeader } from "~/components/ui";
import { TimestampCell } from "~/components/cells";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import {
    useClusterCredentials,
    useCreateClusterCredential,
    useListNamespaces,
    useRevokeClusterCredential,
    useRotateClusterCredential,
} from "~/api/queries";

type ClusterCredential = components["schemas"]["ClusterCredentialResponse"];

/** The secret the agent chart reads its key from (chart values apiKey.*). */
export function agentSecretCommand(key: string): string {
    return [
        "kubectl create namespace ocidex-agent --dry-run=client -o yaml | kubectl apply -f -",
        "kubectl -n ocidex-agent create secret generic ocidex-k8s-agent-secrets \\",
        `  --from-literal=OCIDEX_API_KEY='${key}' \\`,
        "  --dry-run=client -o yaml | kubectl apply -f -",
    ].join("\n");
}

/**
 * AgentCredentials lists and manages the cluster's agent credentials
 * (ocidex-70eo.5): API keys bound to this cluster that can push its inventory
 * and nothing else. Shown only to a caller holding manage_cluster on the
 * cluster's namespace, which is what every operation behind it requires.
 */
export function AgentCredentials(props: { clusterId: string; namespaceId: string | undefined }) {
    const toast = useToast();
    const namespaces = useListNamespaces();
    const canManage = createMemo(() => {
        const ns = (namespaces.data?.data ?? []).find((n) => n.id === props.namespaceId);
        return (ns?.capabilities ?? []).includes("manage_cluster");
    });
    const creds = useClusterCredentials(() => props.clusterId, canManage);
    const create = useCreateClusterCredential();
    const rotate = useRotateClusterCredential();
    const revoke = useRevokeClusterCredential();
    const [revealed, setRevealed] = createSignal<string | null>(null);

    const busy = () => create.isPending || rotate.isPending || revoke.isPending;

    const columns: Column<ClusterCredential>[] = [
        { header: "Name", render: (c) => <>{c.name}</> },
        { header: "Prefix", render: (c) => <code>{c.prefix}…</code> },
        { header: "Minted by", render: (c) => <>{c.ownerName ?? "—"}</> },
        { header: "Created", render: (c) => <TimestampCell iso={c.createdAt} /> },
        {
            header: "Last used",
            render: (c) => (
                <Show when={c.lastUsedAt} fallback={<span class="text-muted">Never</span>}>
                    {(t) => <TimestampCell iso={t()} />}
                </Show>
            ),
        },
        {
            header: "",
            render: (c) => (
                <div class="flex justify-end gap-2">
                    <Button
                        size="sm"
                        disabled={busy()}
                        title="Replace with a new key; the agent fails until it gets it"
                        onClick={() => {
                            if (!window.confirm(`Rotate "${c.name}"? The agent stops pushing until its secret holds the new key.`)) return;
                            rotate.mutate(
                                { id: props.clusterId, credentialId: c.id },
                                {
                                    onSuccess: (d) => setRevealed(d.key ?? null),
                                    onError: () => toast("Failed to rotate credential", "error"),
                                },
                            );
                        }}
                    >
                        Rotate
                    </Button>
                    <Button
                        size="sm"
                        disabled={busy()}
                        onClick={() => {
                            if (!window.confirm(`Revoke "${c.name}"? An agent using it stops pushing.`)) return;
                            revoke.mutate(
                                { id: props.clusterId, credentialId: c.id },
                                {
                                    onSuccess: () => toast("Credential revoked", "success"),
                                    onError: () => toast("Failed to revoke credential", "error"),
                                },
                            );
                        }}
                    >
                        Revoke
                    </Button>
                </div>
            ),
        },
    ];

    return (
        <Show when={canManage()}>
            <Card class="mt-4" data-testid="agent-credentials">
                <CardHeader title="Agent credentials" />
                <p class="text-muted">
                    A credential can push this cluster&apos;s inventory and do nothing else. It acts
                    with the roles of the person who minted it, so it stops working if they lose
                    the ability to push here.
                </p>

                <Show when={revealed()}>
                    {(key) => (
                        <Card tone="success" class="mb-3">
                            <p class="mb-2">
                                <strong>Credential created.</strong> Copy it now — it will not be
                                shown again. This stores it where the agent chart reads it:
                            </p>
                            <pre class="agent-setup-commands">{agentSecretCommand(key())}</pre>
                            <div class="flex gap-2">
                                <Button
                                    variant="primary"
                                    onClick={() => {
                                        void copyText(agentSecretCommand(key())).then(() =>
                                            toast("Copied to clipboard", "success"),
                                        );
                                    }}
                                >
                                    Copy command
                                </Button>
                                <Button onClick={() => setRevealed(null)}>Dismiss</Button>
                            </div>
                        </Card>
                    )}
                </Show>

                <div class="mb-3">
                    <DataTable
                        columns={columns}
                        rows={creds.data}
                        loading={creds.isFetching}
                        isError={creds.isError}
                        error={creds.error}
                        emptyTitle="No credentials yet"
                    />
                </div>

                <Button
                    variant="primary"
                    disabled={busy()}
                    onClick={() =>
                        create.mutate(
                            { id: props.clusterId },
                            {
                                onSuccess: (d) => setRevealed(d.key ?? null),
                                onError: () => toast("Failed to create credential", "error"),
                            },
                        )
                    }
                >
                    New credential
                </Button>
            </Card>
        </Show>
    );
}
