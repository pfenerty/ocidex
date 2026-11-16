import { Show, createSignal } from "solid-js";
import { ScanJobsView } from "./jobs/ScanJobsView";
import { EnrichmentJobsView } from "./jobs/EnrichmentJobsView";
import { Segmented } from "~/components/ui";

type Pipeline = "scan" | "enrichment";

/** JobsTab switches between the two job queues; each view owns its own filters. */
export function JobsTab() {
    const [pipeline, setPipeline] = createSignal<Pipeline>("scan");
    return (
        <div>
            <Segmented
                class="mb-4"
                label="Job queue"
                options={[
                    { id: "scan", label: "Scan jobs" },
                    { id: "enrichment", label: "Enrichment jobs" },
                ]}
                value={pipeline()}
                onChange={setPipeline}
            />
            <Show when={pipeline() === "scan"} fallback={<EnrichmentJobsView />}>
                <ScanJobsView />
            </Show>
        </div>
    );
}
