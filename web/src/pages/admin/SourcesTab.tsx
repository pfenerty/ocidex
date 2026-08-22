import "./SourcesTab.css";
import { createEffect, createMemo, createSignal } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import {
    useListRegistries,
    useListScanJobs,
    useRegistryTrustSummary,
    useListSources,
    useListNamespaces,
} from "~/api/queries";
import { RegistryFormDialog, type RegistryDialogHandle } from "./sources/RegistryFormDialog";
import { registryColumns } from "./sources/registryColumns";
import { prefillForHost } from "./sources/registryTypes";
import { NamespaceGroups } from "./sources/NamespaceGroups";
import { DriftFeedCard } from "./sources/DriftFeedCard";
import { WebhookSecretBanner } from "./sources/WebhookSecretBanner";

/**
 * SourcesTab lists every ingest channel grouped by namespace, and owns the
 * cross-cutting state the pieces share: the add/edit dialog handle and the
 * one-shot webhook secret.
 */
export function SourcesTab() {
    const query = useListRegistries();
    const sourcesQuery = useListSources();
    const namespacesQuery = useListNamespaces();
    const activeJobs = useListScanJobs(() => ({ limit: 100 }));
    const trustSummary = useRegistryTrustSummary();

    const [revealedSecret, setRevealedSecret] = createSignal<string | null>(null);
    let dialog: RegistryDialogHandle | undefined;

    // Deep links carry the intent, not just the destination: the cluster Gaps
    // tab sends a reader here because a specific host has no registry, or
    // because a specific registry is the thing to look at. Landing on a list of
    // every source with no indication of why would make them do the search
    // again by hand.
    //
    // The param is cleared once acted on, so a reload or a back-navigation does
    // not re-open the dialog over whatever the reader has since typed.
    const [searchParams, setSearchParams] = useSearchParams();
    const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

    createEffect(() => {
        if (one(searchParams.add) !== "1") return;
        const host = one(searchParams.host);
        dialog?.openAdd(host === undefined || host === "" ? undefined : prefillForHost(host));
        setSearchParams({ add: undefined, host: undefined }, { replace: true });
    });

    createEffect(() => {
        const id = one(searchParams.registry);
        if (id === undefined || id === "") return;
        // Wait for the list before deciding the id is unknown — until it loads,
        // "not found" and "not fetched yet" look identical.
        const registries = query.data?.data;
        if (registries === undefined || registries === null) return;
        const match = registries.find((r) => r.id === id);
        if (match !== undefined) dialog?.openEdit(match);
        setSearchParams({ registry: undefined }, { replace: true });
    });

    const activeByRegistry = createMemo(() => {
        const counts = new Map<string, number>();
        for (const job of activeJobs.data?.data ?? []) {
            if ((job.state === "running" || job.state === "queued") && job.registry_id !== undefined) {
                counts.set(job.registry_id, (counts.get(job.registry_id) ?? 0) + 1);
            }
        }
        return counts;
    });

    const trustByRegistry = createMemo(() => {
        const byRegistry = new Map<string, Map<string, number>>();
        for (const row of trustSummary.data?.data ?? []) {
            let statuses = byRegistry.get(row.registryId);
            if (statuses === undefined) {
                statuses = new Map<string, number>();
                byRegistry.set(row.registryId, statuses);
            }
            statuses.set(row.signingStatus, row.count);
        }
        return byRegistry;
    });

    const columns = registryColumns({
        activeByRegistry,
        trustByRegistry,
        onEdit: (reg) => dialog?.openEdit(reg),
        onSecretRevealed: setRevealedSecret,
    });

    return (
        <>
            <WebhookSecretBanner secret={revealedSecret()} onDismiss={() => setRevealedSecret(null)} />

            <div style={{ "margin-bottom": "1rem" }}>
                <button class="btn btn-primary" onClick={() => dialog?.openAdd()}>Add Registry</button>
            </div>

            <RegistryFormDialog ref={(h) => (dialog = h)} onSecretRevealed={setRevealedSecret} />

            <NamespaceGroups
                columns={columns}
                registries={query.data?.data ?? []}
                sources={sourcesQuery.data?.data ?? []}
                namespaces={namespacesQuery.data?.data ?? []}
                loading={sourcesQuery.isLoading || query.isLoading}
                isError={sourcesQuery.isError || query.isError}
                error={sourcesQuery.error ?? query.error}
            />

            <DriftFeedCard />
        </>
    );
}
