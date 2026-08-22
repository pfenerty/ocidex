import { Show, createSignal } from "solid-js";
import { ScanJobsView } from "./jobs/ScanJobsView";
import { EnrichmentJobsView } from "./jobs/EnrichmentJobsView";

type Pipeline = "scan" | "enrichment";

const activeStyle = { "border-color": "var(--color-secondary)", color: "var(--color-secondary)" };

/** JobsTab switches between the two job queues; each view owns its own filters. */
export function JobsTab() {
    const [pipeline, setPipeline] = createSignal<Pipeline>("scan");
    return (
        <div>
            <div style={{ display: "flex", gap: "0.25rem", "margin-bottom": "1rem" }}>
                <button
                    class="btn"
                    aria-pressed={pipeline() === "scan"}
                    onClick={() => setPipeline("scan")}
                    style={pipeline() === "scan" ? activeStyle : {}}
                >
                    Scan jobs
                </button>
                <button
                    class="btn"
                    aria-pressed={pipeline() === "enrichment"}
                    onClick={() => setPipeline("enrichment")}
                    style={pipeline() === "enrichment" ? activeStyle : {}}
                >
                    Enrichment jobs
                </button>
            </div>
            <Show when={pipeline() === "scan"} fallback={<EnrichmentJobsView />}>
                <ScanJobsView />
            </Show>
        </div>
    );
}
