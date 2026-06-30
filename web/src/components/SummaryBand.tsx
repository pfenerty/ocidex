import "./SummaryBand.css";
import { Show } from "solid-js";
import type { OCIMetadata, Provenance } from "~/api/client";
import { relativeDate } from "~/utils/format";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { ShieldIcon, OciIcon, ContainerIcon } from "./metadata/OciIcons";

export type SbomTab = "packages" | "provenance" | "image" | "raw";

// shortBuilder renders a recognizable builder name from a SLSA builder id URL.
function shortBuilder(id: string | undefined): string | undefined {
    if (id === undefined || id === "") return undefined;
    if (id.includes("tekton")) return "Tekton Chains";
    if (id.includes("github")) return "GitHub Actions";
    return id.replace(/^https?:\/\//, "");
}

export default function SummaryBand(props: {
    provenance: Provenance | undefined;
    metadata: OCIMetadata | undefined;
    packageCount: number | undefined;
    ecosystems: string[];
    specVersion: string;
    ingestedAt: string;
    active: SbomTab;
    onSelect: (tab: SbomTab) => void;
}) {
    const trust = () => trustStatus(props.provenance);
    const platform = () => {
        const m = props.metadata;
        if (m === undefined) return undefined;
        const p = [m.os, m.architecture].filter(Boolean).join("/");
        return p === "" ? undefined : p;
    };

    return (
        <div class="summary-band">
            {/* Provenance */}
            <button
                class={`summary-tile ${props.active === "provenance" ? "active" : ""}`}
                onClick={() => props.onSelect("provenance")}
            >
                <span class="summary-tile-head">
                    <ShieldIcon />
                    Provenance
                </span>
                <Show
                    when={trust()}
                    fallback={<span class="summary-tile-value text-muted">Not enriched</span>}
                >
                    {(t) => <span class={`${trustBadgeClass(t().variant)} summary-tile-value`}>{t().label}</span>}
                </Show>
                <span class="summary-tile-sub">
                    {shortBuilder(props.provenance?.builderId) ??
                        (props.provenance !== undefined ? "no signature" : "—")}
                </span>
            </button>

            {/* Image */}
            <button
                class={`summary-tile ${props.active === "image" ? "active" : ""}`}
                onClick={() => props.onSelect("image")}
            >
                <span class="summary-tile-head">
                    <OciIcon />
                    Image
                </span>
                <span class="summary-tile-value">{platform() ?? "—"}</span>
                <span class="summary-tile-sub">
                    <Show when={props.metadata?.baseName} fallback="OCI image">
                        {(base) => (
                            <>
                                <ContainerIcon /> {base()}
                            </>
                        )}
                    </Show>
                </span>
            </button>

            {/* Packages */}
            <button
                class={`summary-tile ${props.active === "packages" ? "active" : ""}`}
                onClick={() => props.onSelect("packages")}
            >
                <span class="summary-tile-head">Packages</span>
                <span class="summary-tile-value">{props.packageCount ?? "—"}</span>
                <span class="summary-tile-sub">
                    {props.ecosystems.length > 0 ? props.ecosystems.join(" · ") : "components"}
                </span>
            </button>

            {/* SBOM */}
            <button
                class={`summary-tile ${props.active === "raw" ? "active" : ""}`}
                onClick={() => props.onSelect("raw")}
            >
                <span class="summary-tile-head">SBOM</span>
                <span class="summary-tile-value">CycloneDX {props.specVersion}</span>
                <span class="summary-tile-sub">ingested {relativeDate(props.ingestedAt)}</span>
            </button>
        </div>
    );
}
