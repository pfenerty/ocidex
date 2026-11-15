import "./ClusterDetail/ClusterDetail.css";
import { For, Show, createEffect, createMemo, createSignal } from "solid-js";
import { A, useNavigate } from "@solidjs/router";
import { Breadcrumb, Button, Card, CardHeader, FormField, PageHeader } from "~/components/ui";
import { useToast } from "~/context/toast";
import { useConnectCluster, useMyNamespaces } from "~/api/queries";
import { rememberInstallKey } from "./ClusterDetail/installKey";

/**
 * ConnectCluster is step one of connecting a cluster (ocidex-70eo.6): name it,
 * and OCIDex creates it together with an agent credential. Step two, the
 * install command, and step three, waiting for the first snapshot, happen on
 * the cluster's own page. This is a page rather than a modal because what
 * follows shows a key once and then waits, and a modal is one stray click
 * from losing both (design decision Q1).
 */
export default function ConnectCluster() {
    const navigate = useNavigate();
    const toast = useToast();
    const namespaces = useMyNamespaces();
    const connect = useConnectCluster();

    // Only namespaces the caller can actually connect a cluster in: the API
    // needs both capabilities, and offering the rest is offering a 403.
    const eligible = createMemo(() =>
        (namespaces.data?.data ?? []).filter((ns) => {
            const caps = ns.capabilities;
            return caps === undefined || caps === null || (caps.includes("manage_cluster") && caps.includes("push_inventory"));
        }),
    );

    const [name, setName] = createSignal("");
    const [namespaceId, setNamespaceId] = createSignal("");
    const [description, setDescription] = createSignal("");
    const [autoIngest, setAutoIngest] = createSignal(true);

    // Most people can connect in exactly one namespace; asking them to pick
    // it from a list of one is a step with no decision in it (audit R1).
    createEffect(() => {
        const list = eligible();
        if (namespaceId() === "" && list.length > 0) setNamespaceId(list[0].id);
    });

    function submit(e: Event) {
        e.preventDefault();
        connect.mutate(
            {
                namespaceId: namespaceId(),
                name: name().trim(),
                description: description().trim() === "" ? undefined : description().trim(),
                autoIngest: autoIngest(),
            },
            {
                onSuccess: (res) => {
                    if (res.credential.key !== undefined) {
                        rememberInstallKey(res.cluster.id, {
                            key: res.credential.key,
                            serverUrl: res.credential.serverUrl,
                        });
                    }
                    navigate(`/clusters/${res.cluster.id}`);
                },
                onError: (err) =>
                    toast(
                        err.message.includes("409") || err.message.toLowerCase().includes("conflict")
                            ? "A cluster with that name already exists in this namespace"
                            : "Failed to connect the cluster",
                        "error",
                    ),
            },
        );
    }

    return (
        <>
            <PageHeader
                breadcrumb={<Breadcrumb items={[{ label: "Clusters", href: "/clusters" }, { label: "Connect" }]} />}
                title="Connect a cluster"
                subtitle="Name it, run one command against it, and this page waits for its first report."
            />
            <div class="connect-grid">
                <Card>
                    <form onSubmit={submit} class="grid gap-3">
                        <FormField label="Name">
                            <input
                                id="connect-name"
                                type="text"
                                placeholder="prod-eu-1"
                                value={name()}
                                onInput={(e) => setName(e.currentTarget.value)}
                            />
                        </FormField>
                        <FormField label="Namespace" hint="who can see what it runs; can't be changed later">
                            <select
                                id="connect-namespace"
                                value={namespaceId()}
                                onChange={(e) => setNamespaceId(e.currentTarget.value)}
                            >
                                <For each={eligible()}>{(ns) => <option value={ns.id}>{ns.name}</option>}</For>
                            </select>
                        </FormField>
                        <FormField label="Description">
                            <input
                                id="connect-description"
                                type="text"
                                placeholder="optional"
                                value={description()}
                                onInput={(e) => setDescription(e.currentTarget.value)}
                            />
                        </FormField>
                        <label class="flex items-center gap-2">
                            <input
                                id="connect-auto-ingest"
                                type="checkbox"
                                checked={autoIngest()}
                                onChange={(e) => setAutoIngest(e.currentTarget.checked)}
                            />
                            Scan running images that have no SBOM
                        </label>
                        <Show when={namespaces.isSuccess && eligible().length === 0}>
                            <p class="text-muted">
                                You can&apos;t connect a cluster in any namespace yet: it needs a role that can
                                manage clusters and push inventory. Ask a namespace owner.
                            </p>
                        </Show>
                        <div class="flex gap-2">
                            <Button
                                variant="primary"
                                type="submit"
                                disabled={connect.isPending || name().trim() === "" || namespaceId() === ""}
                            >
                                {connect.isPending ? "Creating…" : "Create and get install command"}
                            </Button>
                            <Button as={A} href="/clusters" end>
                                Cancel
                            </Button>
                        </div>
                    </form>
                </Card>
                <Card>
                    <CardHeader title="What happens next" />
                    <p class="text-muted">
                        OCIDex creates the cluster and an agent credential that can push this cluster&apos;s
                        inventory and do nothing else. You get one command to run against the cluster, and
                        the next page waits for the agent&apos;s first report.
                    </p>
                    <p class="text-muted mb-0">
                        The agent only reads pods. It needs no CRDs, and OCIDex never stores a kubeconfig.
                    </p>
                </Card>
            </div>
        </>
    );
}
