import { For, Show, type Accessor } from "solid-js";
import type { Column } from "~/components/DataTable";
import type { Registry } from "~/api/client";
import { trustBadgeClass, signingStatusLabel, trustStatus } from "~/utils/trust";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import {
    useDeleteRegistry,
    useScanRegistry,
    useRegenerateWebhookSecret,
} from "~/api/queries";
import { hasWebhook, regTypeLabel } from "./registryTypes";

/**
 * registryColumns builds the registry table's columns. It is a function rather
 * than a constant because the action column needs the page's mutations and the
 * live per-registry job/trust counts; call it from a component body so the
 * mutation hooks get an owner.
 */
export function registryColumns(opts: {
    activeByRegistry: Accessor<Map<string, number>>;
    trustByRegistry: Accessor<Map<string, Map<string, number>>>;
    onEdit: (reg: Registry) => void;
    onSecretRevealed: (secret: string) => void;
}): Column<Registry>[] {
    const toast = useToast();
    const deleteReg = useDeleteRegistry();
    const scanReg = useScanRegistry();
    const regenSecret = useRegenerateWebhookSecret();

    const copyWebhookURL = (url: string) => {
        void copyText(url).then(() => {
            toast("Webhook URL copied", "success");
        });
    };

    return [
        {
            header: "Name",
            render: (reg) => (
                <div style={{ display: "flex", "align-items": "center", gap: "0.4rem", "flex-wrap": "wrap" }}>
                    {reg.name}
                    <Show when={(reg.managed_by ?? "") !== ""}>
                        <span
                            class="badge"
                            style={{ "font-size": "0.7rem" }}
                            title={`Configured by ${reg.managed_by ?? ""}${(reg.managed_ref ?? "") === "" ? "" : ` (${reg.managed_ref ?? ""})`} — edits made here are reverted on the next reconcile`}
                        >
                            {reg.managed_by === "kubernetes" ? "Managed by Kubernetes" : `Managed by ${reg.managed_by ?? ""}`}
                        </span>
                    </Show>
                </div>
            ),
        },
        { header: "Type", render: (reg) => <code>{regTypeLabel(reg.type)}</code> },
        { header: "URL", render: (reg) => <code>{reg.url}</code> },
        { header: "Visibility", render: (reg) => <span class="badge">{reg.visibility}</span> },
        {
            header: "Owner",
            render: (reg) => (
                <span class="text-muted text-sm">
                    {reg.owner_username ?? "—"}
                </span>
            ),
        },
        {
            header: "Status",
            render: (reg) => (
                <span style={{ color: reg.enabled ? "var(--color-success)" : "var(--color-text-muted)" }}>
                    {reg.enabled ? "Enabled" : "Disabled"}
                </span>
            ),
        },
        {
            header: "Signing Status",
            render: (reg) => (
                <Show
                    when={(() => {
                        const s = opts.trustByRegistry().get(reg.id);
                        return s !== undefined && s.size > 0 ? s : undefined;
                    })()}
                    fallback={<span class="text-muted">—</span>}
                >
                    {(statuses) => (
                        <div style={{ display: "flex", "flex-wrap": "wrap", gap: "0.3rem" }}>
                            <For each={[...statuses().entries()]}>
                                {([status, count]) => {
                                    const t = trustStatus(status);
                                    return (
                                        <span
                                            class={`${t !== null ? trustBadgeClass(t.variant) : "badge"} text-xs`}
                                            title={signingStatusLabel(status)}
                                        >
                                            {signingStatusLabel(status)}: {count}
                                        </span>
                                    );
                                }}
                            </For>
                        </div>
                    )}
                </Show>
            ),
        },
        { header: "Scan Mode", render: (reg) => <code>{reg.scan_mode}</code> },
        {
            header: "Webhook URL",
            render: (reg) => (
                <div style={{ display: "flex", gap: "0.3rem" }}>
                    <Show when={hasWebhook(reg)} fallback={<span class="text-muted">—</span>}>
                        <button
                            class="btn"
                            style={{ "font-size": "0.75rem", padding: "0.2rem 0.5rem" }}
                            onClick={() => copyWebhookURL(reg.webhook_url)}
                        >
                            Copy URL
                        </button>
                        <button
                            class="btn"
                            style={{ "font-size": "0.75rem", padding: "0.2rem 0.5rem" }}
                            title="Generate a new webhook secret (invalidates the old one)"
                            disabled={regenSecret.isPending}
                            onClick={() => regenSecret.mutate(reg.id, {
                                onSuccess: (data) => opts.onSecretRevealed(data.webhook_secret),
                                onError: () => toast("Failed to regenerate secret", "error"),
                            })}
                        >
                            Regen Secret
                        </button>
                    </Show>
                </div>
            ),
        },
        {
            header: "",
            render: (reg) => (
                <div style={{ display: "flex", gap: "0.4rem" }}>
                    <button class="btn" onClick={() => opts.onEdit(reg)}>
                        Edit
                    </button>
                    <button
                        class="btn"
                        title="Scan new/changed images; already-scanned digests are skipped"
                        onClick={() => scanReg.mutate({ id: reg.id }, {
                            onSuccess: (data) => toast(data.message, "success"),
                            onError: () => toast("Failed to start scan", "error"),
                        })}
                        disabled={scanReg.isPending}
                    >
                        Scan
                    </button>
                    <button
                        class="btn"
                        title="Re-scan every image, including already-scanned digests (repopulates enrichment)"
                        onClick={() => {
                            if (!confirm("Force a full re-scan of every image in this registry, including digests already ingested? This re-pulls and re-scans everything.")) return;
                            scanReg.mutate({ id: reg.id, force: true }, {
                                onSuccess: (data) => toast(data.message, "success"),
                                onError: () => toast("Failed to start scan", "error"),
                            });
                        }}
                        disabled={scanReg.isPending}
                    >
                        Force
                    </button>
                    <Show when={(opts.activeByRegistry().get(reg.id) ?? 0) > 0}>
                        <span class="badge badge-primary text-xs">
                            {opts.activeByRegistry().get(reg.id)} active
                        </span>
                    </Show>
                    <button
                        class="btn"
                        onClick={() => deleteReg.mutate(reg.id, {
                            onSuccess: () => toast("Registry deleted", "success"),
                            onError: () => toast("Failed to delete registry", "error"),
                        })}
                        disabled={deleteReg.isPending}
                    >
                        Delete
                    </button>
                </div>
            ),
        },
    ];
}
