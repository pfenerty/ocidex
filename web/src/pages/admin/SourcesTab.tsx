import "./SourcesTab.css";
import { createMemo, createSignal } from "solid-js";
import {
    useListRegistries,
    useListScanJobs,
    useRegistryTrustSummary,
    useListSources,
} from "~/api/queries";
import { RegistryFormDialog, type RegistryDialogHandle } from "./sources/RegistryFormDialog";
import { registryColumns } from "./sources/registryColumns";
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
    const activeJobs = useListScanJobs(() => ({ limit: 100 }));
    const trustSummary = useRegistryTrustSummary();

    const [revealedSecret, setRevealedSecret] = createSignal<string | null>(null);
    let dialog: RegistryDialogHandle | undefined;

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
                loading={sourcesQuery.isLoading || query.isLoading}
                isError={sourcesQuery.isError || query.isError}
                error={sourcesQuery.error ?? query.error}
            />

            <DriftFeedCard />
        </>
    );
}
