import { For, Show, createMemo, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import { useConfirm } from "~/context/confirm";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { APIKey } from "~/api/client";
import {
    useApprovals,
    useCreateAgentKey,
    useDeleteAPIKey,
    useKeyActivity,
    useKeyPresets,
    useListAPIKeys,
    useMyNamespaces,
} from "~/api/queries";
import type { AgentKeyInput, KeyActivityEntry, PendingAction } from "~/api/queries";
import { Button, Card, CardHeader } from "~/components/ui";
import { TimestampCell } from "~/components/cells";
import "./AgentsTab.css";

type PresetName = AgentKeyInput["preset"];

/** The ocidex-mcp invocation a client config needs, with the key in the environment. */
export function mcpCommand(server: string, key: string): string {
    return `claude mcp add ocidex --env OCIDEX_URL=${server} --env OCIDEX_API_KEY=${key} -- ocidex-mcp`;
}

/**
 * Agents: the keys programs use on your behalf (ADR-0058). Held writes waiting
 * for you come first, because they are the only thing here that needs an
 * answer; then the agent keys, each with what it has done; then the form that
 * makes one. A key is made from a preset and limited to chosen namespaces, and
 * it always expires.
 */
export function AgentsTab() {
    const toast = useToast();
    const confirm = useConfirm();
    const keys = useListAPIKeys();
    const presets = useKeyPresets();
    const namespaces = useMyNamespaces();
    const pending = useApprovals(() => "pending");
    const createKey = useCreateAgentKey();
    const deleteKey = useDeleteAPIKey();

    const agentKeys = createMemo(() => (keys.data?.keys ?? []).filter((k) => k.kind === "agent"));
    const nsName = (id: string) => (namespaces.data?.data ?? []).find((n) => n.id === id)?.name ?? id;

    const [name, setName] = createSignal("");
    const [label, setLabel] = createSignal("");
    const [preset, setPreset] = createSignal<PresetName>("analyst");
    const [chosen, setChosen] = createSignal<string[]>([]);
    const [days, setDays] = createSignal(30);
    const [revealed, setRevealed] = createSignal<string | null>(null);
    const [openActivity, setOpenActivity] = createSignal<string | null>(null);

    const maxDays = () => presets.data?.maxExpiryDays ?? 90;
    const selectedPreset = () => (presets.data?.presets ?? []).find((p) => p.name === preset());
    const canCreate = () => name().trim() !== "" && chosen().length > 0 && !createKey.isPending;

    function toggleNamespace(id: string, on: boolean) {
        setChosen((cur) => (on ? [...cur, id] : cur.filter((n) => n !== id)));
    }

    function handleCreate(e: Event) {
        e.preventDefault();
        if (!canCreate()) return;
        const expires = new Date(Date.now() + Math.min(days(), maxDays()) * 24 * 60 * 60 * 1000);
        createKey.mutate(
            {
                name: name().trim(),
                preset: preset(),
                namespaces: chosen(),
                agentLabel: label().trim() === "" ? undefined : label().trim(),
                expiresAt: expires.toISOString(),
            },
            {
                onSuccess: (out) => {
                    setRevealed(out.key);
                    setName("");
                    setLabel("");
                    setChosen([]);
                },
                onError: () => toast("Could not create the agent key", "error"),
            },
        );
    }

    const columns: Column<APIKey>[] = [
        {
            header: "Agent",
            render: (k) => (
                <span>
                    <strong>{k.name}</strong>
                    <Show when={k.agentLabel}>{(l) => <span class="text-muted"> · {l()}</span>}</Show>
                </span>
            ),
        },
        { header: "Namespaces", render: (k) => (k.namespaces ?? []).map(nsName).join(", ") },
        {
            header: "Can",
            render: (k) => (
                <span>
                    {(k.capabilities ?? []).join(", ")}
                    <Show when={(k.approvalRequired ?? []).length > 0}>
                        <span class="text-muted"> (approval: {(k.approvalRequired ?? []).join(", ")})</span>
                    </Show>
                </span>
            ),
        },
        {
            header: "Expires",
            render: (k) => <Show when={k.expiresAt} fallback="never">{(t) => <TimestampCell iso={t()} />}</Show>,
        },
        {
            header: "Last used",
            render: (k) => <Show when={k.lastUsedAt} fallback="never">{(t) => <TimestampCell iso={t()} />}</Show>,
        },
        {
            header: "",
            render: (k) => (
                <span class="flex gap-2">
                    <Button size="sm" onClick={() => setOpenActivity(openActivity() === k.id ? null : k.id)}>
                        {openActivity() === k.id ? "Hide activity" : "Activity"}
                    </Button>
                    <Button
                        size="sm"
                        variant="danger"
                        disabled={deleteKey.isPending}
                        onClick={() =>
                            void (async () => {
                                const ok = await confirm({
                                    title: `Revoke ${k.name}?`,
                                    body: "The agent using it stops working immediately. Pending approvals it asked for can no longer run.",
                                    confirmLabel: "Revoke",
                                });
                                if (!ok) return;
                                deleteKey.mutate(k.id, {
                                    onSuccess: () => toast("Agent key revoked", "success"),
                                    onError: () => toast("Could not revoke the key", "error"),
                                });
                            })()
                        }
                    >
                        Revoke
                    </Button>
                </span>
            ),
        },
    ];

    return (
        <>
            <Show when={(pending.data ?? []).length > 0}>
                <Card class="mb-4 agents-inbox">
                    <CardHeader title="Waiting for your approval" count={(pending.data ?? []).length} />
                    <ul class="agents-inbox-list">
                        <For each={pending.data}>{(a) => <PendingRow action={a} />}</For>
                    </ul>
                </Card>
            </Show>

            <Show when={revealed()}>
                {(key) => (
                    <Card tone="success" class="mb-4">
                        <p class="mb-2">
                            <strong>Agent key created.</strong> Copy it now; it will not be shown again. To connect an
                            MCP client:
                        </p>
                        <code class="mb-2 block break-all">{mcpCommand(window.location.origin, key())}</code>
                        <div class="flex gap-2">
                            <Button
                                variant="primary"
                                onClick={() =>
                                    void copyText(mcpCommand(window.location.origin, key())).then(() =>
                                        toast("Copied to clipboard", "success"),
                                    )
                                }
                            >
                                Copy command
                            </Button>
                            <Button onClick={() => void copyText(key()).then(() => toast("Copied to clipboard", "success"))}>
                                Copy key only
                            </Button>
                            <Button onClick={() => setRevealed(null)}>Dismiss</Button>
                        </div>
                    </Card>
                )}
            </Show>

            <DataTable
                caption={<CardHeader title="Agent keys" count={agentKeys().length} />}
                columns={columns}
                rows={keys.data ? agentKeys() : undefined}
                loading={keys.isFetching}
                isError={keys.isError}
                error={keys.error}
                emptyTitle="No agent keys yet"
                emptyMessage="Create one below to let an agent such as Claude Code work in your namespaces."
            />
            <Show when={openActivity()}>{(id) => <ActivityPanel keyId={id()} />}</Show>

            <Card class="mt-4">
                <CardHeader title="Create an agent key" />
                <form onSubmit={handleCreate} class="agents-form">
                    <label>
                        Name
                        <input type="text" value={name()} onInput={(e) => setName(e.currentTarget.value)} placeholder="e.g. remediation bot" />
                    </label>
                    <label>
                        Client
                        <input type="text" value={label()} onInput={(e) => setLabel(e.currentTarget.value)} placeholder="e.g. Claude Code on my laptop" />
                    </label>
                    <label>
                        What it may do
                        <select value={preset()} onChange={(e) => setPreset(e.currentTarget.value as PresetName)}>
                            <For each={presets.data?.presets ?? []}>{(p) => <option value={p.name}>{p.title}</option>}</For>
                        </select>
                    </label>
                    <Show when={selectedPreset()}>{(p) => <p class="text-muted agents-form-wide">{p().description}</p>}</Show>
                    <fieldset class="agents-form-wide agents-namespaces">
                        <legend>Namespaces it may work in</legend>
                        <For each={namespaces.data?.data ?? []} fallback={<span class="text-muted">You are not a member of any namespace.</span>}>
                            {(n) => (
                                <label>
                                    <input type="checkbox" checked={chosen().includes(n.id)} onChange={(e) => toggleNamespace(n.id, e.currentTarget.checked)} />
                                    {n.name}
                                </label>
                            )}
                        </For>
                    </fieldset>
                    <label>
                        Expires after
                        <select value={days()} onChange={(e) => setDays(Number(e.currentTarget.value))}>
                            <For each={[7, 30, 90].filter((d) => d <= maxDays())}>{(d) => <option value={d}>{d} days</option>}</For>
                        </select>
                    </label>
                    <div class="agents-form-wide">
                        <Button variant="primary" type="submit" disabled={!canCreate()}>
                            Create agent key
                        </Button>
                    </div>
                </form>
            </Card>
        </>
    );
}

/** One held action in the inbox: the effect OCIDex wrote, and a link to decide it. */
function PendingRow(props: { action: PendingAction }) {
    return (
        <li class="agents-inbox-row">
            <span class="agents-inbox-effect">{props.action.effect}</span>
            <span class="text-muted text-sm">
                {props.action.agentLabel ?? "an agent"} · <TimestampCell iso={props.action.createdAt} />
            </span>
            <A href={`/approvals/${props.action.id}`}>Review</A>
        </li>
    );
}

/** What one agent key did: writes, holds and refusals, newest first. */
function ActivityPanel(props: { keyId: string }) {
    const activity = useKeyActivity(() => props.keyId, () => true);
    const columns: Column<KeyActivityEntry>[] = [
        { header: "When", render: (a) => <TimestampCell iso={a.occurredAt} /> },
        { header: "Request", class: "font-mono text-sm", render: (a) => `${a.method} ${a.route}` },
        { header: "Tool", render: (a) => a.tool ?? "" },
        {
            header: "Outcome",
            render: (a) => (
                <Show
                    when={a.pendingActionId}
                    fallback={<span classList={{ "agents-refused": a.status >= 400 }}>{a.status}</span>}
                >
                    {(id) => <A href={`/approvals/${id()}`}>held for approval</A>}
                </Show>
            ),
        },
    ];
    return (
        <div class="mt-2">
            <DataTable
                caption={<CardHeader title="Activity" />}
                columns={columns}
                rows={activity.data}
                loading={activity.isFetching}
                isError={activity.isError}
                error={activity.error}
                emptyTitle="No writes or refusals recorded for this key"
            />
        </div>
    );
}
