import { For, Show, type Accessor } from "solid-js";
import type { Column } from "~/components/DataTable";
import { APIClientError, type Registry } from "~/api/client";
import type { components } from "~/types/openapi";
import { A } from "@solidjs/router";

type RegistryClusterGap = components["schemas"]["RegistryClusterGapResponse"];
import { trustBadgeClass, signingStatusLabel, trustStatus } from "~/utils/trust";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import {
    useDeleteRegistry,
    useScanRegistry,
    useRegenerateWebhookSecret,
} from "~/api/queries";
import { hasWebhook, regTypeLabel } from "./registryTypes";
import { Button } from "~/components/ui";
import { formatDateTime } from "~/utils/format";
import { useConfirm } from "~/context/confirm";

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
    /** The caller's capabilities in the registry's namespace (ADR-046). */
    capsFor: (registryID: string) => Set<string>;
    /** The cluster gaps each registry serves (ocidex-70eo.14); absent hides the column. */
    gapsFor?: (registryID: string) => RegistryClusterGap[];
}): Column<Registry>[] {
    const toast = useToast();
    const confirm = useConfirm();
    const deleteReg = useDeleteRegistry();
    const scanReg = useScanRegistry();
    const regenSecret = useRegenerateWebhookSecret();

    // 409: a scan of this registry is already queued or running, so this
    // click changed nothing (ocidex-89c9.2). Say so, not "failed".
    const reportScanFailure = (err: unknown) => {
        if (err instanceof APIClientError && err.status === 409) {
            toast("A scan of this registry is already in progress", "info");
            return;
        }
        toast("Failed to start scan", "error");
    };

    const copyWebhookURL = (url: string) => {
        void copyText(url).then(() => {
            toast("Webhook URL copied", "success");
        });
    };

    return [
        {
            header: "Name",
            render: (reg) => (
                <div class="flex flex-wrap items-center gap-[0.4rem]">
                    {reg.name}
                    <Show when={(reg.managedBy ?? "") !== ""}>
                        <span
                            class="badge text-[0.7rem]"
                            title={`Configured by ${reg.managedBy ?? ""}${(reg.managedRef ?? "") === "" ? "" : ` (${reg.managedRef ?? ""})`} — edits made here are reverted on the next reconcile`}
                        >
                            {reg.managedBy === "kubernetes" ? "Managed by Kubernetes" : `Managed by ${reg.managedBy ?? ""}`}
                        </span>
                    </Show>
                </div>
            ),
        },
        // Labels, not machine strings: plain text. In mono they wrapped to four
        // lines and helped push the table past its card (ocidex-s8i4).
        { header: "Type", render: (reg) => <span class="text-sm">{regTypeLabel(reg.type)}</span> },
        { header: "URL", render: (reg) => <code>{reg.url}</code> },
        { header: "Visibility", render: (reg) => <span class="badge">{reg.visibility}</span> },
        {
            header: "Status",
            render: (reg) => (
                <span class={reg.enabled ? "text-[var(--color-success)]" : "text-[var(--color-text-muted)]"}>
                    {reg.enabled ? "Enabled" : "Disabled"}
                </span>
            ),
        },
        ...(opts.gapsFor !== undefined
            ? [
                  {
                      // Which running images this registry would close the gap for,
                      // so fixing a registry reads as fixing something specific
                      // (ocidex-70eo.14).
                      header: "Cluster gaps",
                      render: (reg: Registry) => {
                          const gaps = opts.gapsFor?.(reg.id) ?? [];
                          return (
                              <Show when={gaps.length > 0} fallback={<span class="text-muted">—</span>}>
                                  <div class="grid gap-0.5 text-sm" data-testid="registry-gaps">
                                      <For each={gaps}>
                                          {(g) => (
                                              <A href={`/clusters/${g.clusterId}?tab=gaps`}>
                                                  {g.images.toLocaleString()} running in {g.clusterName}
                                                  <span class="text-muted">
                                                      {" "}
                                                      ·{" "}
                                                      {!reg.enabled
                                                          ? "closes when enabled"
                                                          : g.ready === g.images
                                                            ? "ready to ingest"
                                                            : g.ready === 0
                                                              ? "blocked: see gaps"
                                                              : `${g.ready.toLocaleString()} of ${g.images.toLocaleString()} ready`}
                                                  </span>
                                              </A>
                                          )}
                                      </For>
                                  </div>
                              </Show>
                          );
                      },
                  },
              ]
            : []),
        {
            // What the scan window selected on the latest walk (ADR-0053).
            header: "Last walk",
            render: (reg) => (
                <Show when={reg.lastWalk} fallback={<span class="text-[var(--color-text-muted)]">never</span>}>
                    {(w) => (
                        <Show
                            when={w().error === undefined || w().error === ""}
                            fallback={<span class="text-[var(--color-danger)]" title={w().error}>failed</span>}
                        >
                            <span
                                data-testid="last-walk"
                                title={`${w().repositories} repositories, ${w().matched} matching tags, ${w().skippedByAge} too old. ${formatDateTime(w().at)}`}
                            >
                                {w().selected} tags
                                <Show when={w().skippedByLimit > 0}>
                                    <span class="text-[var(--color-text-muted)]"> (+{w().skippedByLimit} past limit)</span>
                                </Show>
                                {/* Jobs that walk submitted, not jobs still waiting:
                                    the "N active" badge counts those, and the two
                                    read as a contradiction when both said "queued"
                                    (ocidex-nps9.25). */}
                                {" · "}{w().queued} sent to scan
                            </span>
                        </Show>
                    )}
                </Show>
            ),
        },
        {
            header: "Signing status",
            render: (reg) => (
                <Show
                    when={(() => {
                        const s = opts.trustByRegistry().get(reg.id);
                        return s !== undefined && s.size > 0 ? s : undefined;
                    })()}
                    fallback={<span class="text-muted">—</span>}
                >
                    {(statuses) => (
                        <div class="flex flex-wrap gap-[0.3rem]">
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
        { header: "Scan mode", render: (reg) => <span class="text-sm">{reg.scanMode}</span> },
        {
            header: "Webhook URL",
            render: (reg) => (
                <div class="flex gap-[0.3rem]">
                    <Show when={hasWebhook(reg)} fallback={<span class="text-muted">—</span>}>
                        <Button
                            size="sm"
                            onClick={() => copyWebhookURL(reg.webhookUrl)}
                        >
                            Copy URL
                        </Button>
                        <Show when={opts.capsFor(reg.id).has("read_secret")}>
                        <Button
                            size="sm"
                            title="Generate a new webhook secret (invalidates the old one)"
                            disabled={regenSecret.isPending}
                            onClick={() => regenSecret.mutate(reg.id, {
                                onSuccess: (data) => opts.onSecretRevealed(data.webhookSecret),
                                onError: () => toast("Failed to regenerate secret", "error"),
                            })}
                        >
                            Regen Secret
                        </Button>
                        </Show>
                    </Show>
                </div>
            ),
        },
        {
            header: "",
            render: (reg) => {
                const caps = () => opts.capsFor(reg.id);
                const canManage = () => caps().has("manage_source");
                const canScan = () => caps().has("trigger_scan");
                return (
                    <Show
                        when={canManage() || canScan()}
                        fallback={
                            <span class="text-muted text-sm whitespace-nowrap" title="Your role in this namespace does not allow changing or scanning it">
                                Read only
                            </span>
                        }
                    >
                        {/* Small and wrapping: four full-size buttons in one
                            row were most of why the table overflowed a 1440px
                            screen and clipped Delete (ocidex-s8i4). */}
                        <div class="flex max-w-[12.5rem] flex-wrap justify-end gap-[0.3rem]">
                            <Show when={canManage()}>
                                <Button size="sm" onClick={() => opts.onEdit(reg)}>
                                    Edit
                                </Button>
                            </Show>
                            <Show when={canScan()}>
                                <Button
                                    size="sm"
                                    title="Scan new/changed images; already-scanned digests are skipped"
                                    onClick={() => scanReg.mutate({ id: reg.id }, {
                                        onSuccess: (data) => toast(data.message, "success"),
                                        onError: (err) => reportScanFailure(err),
                                    })}
                                    disabled={scanReg.isPending}
                                >
                                    Scan
                                </Button>
                                <Button
                                    size="sm"
                                    title="Re-scan every image, including already-scanned digests (repopulates enrichment)"
                                    onClick={() => void (async () => {
                                        const ok = await confirm({
                                            title: `Re-scan everything in ${reg.name}?`,
                                            body: "Every image is pulled and scanned again, including digests already ingested. On a large registry this takes a while and uses registry rate limit.",
                                            confirmLabel: "Re-scan all",
                                            tone: "default",
                                        });
                                        if (!ok) return;
                                        scanReg.mutate({ id: reg.id, force: true }, {
                                            onSuccess: (data) => toast(data.message, "success"),
                                            onError: (err) => reportScanFailure(err),
                                        });
                                    })()}
                                    disabled={scanReg.isPending}
                                >
                                    Re-scan all
                                </Button>
                            </Show>
                            <Show when={(opts.activeByRegistry().get(reg.id) ?? 0) > 0}>
                                <span class="badge badge-primary text-xs">
                                    {opts.activeByRegistry().get(reg.id)} active
                                </span>
                            </Show>
                            <Show when={canManage()}>
                                <Button
                                    size="sm"
                                    variant="danger"
                                    onClick={() => void (async () => {
                                        const ok = await confirm({
                                            title: `Delete registry ${reg.name}?`,
                                            body: "Polling stops and the registry's settings and credentials are removed. Artifacts already ingested from it stay in the catalog.",
                                            confirmLabel: "Delete registry",
                                        });
                                        if (!ok) return;
                                        deleteReg.mutate(reg.id, {
                                            onSuccess: () => toast("Registry deleted", "success"),
                                            onError: () => toast("Failed to delete registry", "error"),
                                        });
                                    })()}
                                    disabled={deleteReg.isPending}
                                >
                                    Delete
                                </Button>
                            </Show>
                        </div>
                    </Show>
                );
            },
        },
    ];
}
