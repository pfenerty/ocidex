import { Show, createSignal } from "solid-js";
import { ScanJobsView } from "./jobs/ScanJobsView";
import { EnrichmentJobsView } from "./jobs/EnrichmentJobsView";
import { Button } from "~/components/ui";

type Pipeline = "scan" | "enrichment";

const activeClass = "border-[var(--color-secondary)] text-[var(--color-secondary)]";

/** JobsTab switches between the two job queues; each view owns its own filters. */
export function JobsTab() {
    const [pipeline, setPipeline] = createSignal<Pipeline>("scan");
    return (
        <div>
            <div class="mb-4 flex gap-1">
                <Button
                    aria-pressed={pipeline() === "scan"}
                    onClick={() => setPipeline("scan")}
                    class={pipeline() === "scan" ? activeClass : undefined}
                >
                    Scan jobs
                </Button>
                <Button
                    aria-pressed={pipeline() === "enrichment"}
                    onClick={() => setPipeline("enrichment")}
                    class={pipeline() === "enrichment" ? activeClass : undefined}
                >
                    Enrichment jobs
                </Button>
            </div>
            <Show when={pipeline() === "scan"} fallback={<EnrichmentJobsView />}>
                <ScanJobsView />
            </Show>
        </div>
    );
}
