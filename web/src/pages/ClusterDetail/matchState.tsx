import { StatusPill } from "~/components/ui";
import type { WorkloadMatchState } from "~/api/client";

/**
 * How each match state is presented. The label is the load-bearing part: hue
 * alone cannot carry "this is a gap, not a pass" (the same reasoning as
 * VulnBadge's lightness-not-hue scale), so every state says in words what it
 * is, and the two gap states say *which* gap so they stay distinguishable from
 * each other as well as from a match.
 */
export const MATCH_PRESENTATION: Record<
    WorkloadMatchState,
    { label: string; variant: "success" | "warning" | "danger"; title: string }
> = {
    exact: {
        label: "matched",
        variant: "success",
        title: "The running digest matches an ingested SBOM exactly",
    },
    index: {
        label: "index match",
        variant: "success",
        title: "The runtime reported the multi-arch index digest; the SBOM shown is for one platform of that index",
    },
    unknown: {
        label: "no SBOM",
        variant: "danger",
        title: "A valid digest that matches nothing ingested — this image has not been assessed",
    },
    unresolvable: {
        label: "no digest",
        variant: "warning",
        title: "The runtime reported no registry-addressable digest, so this image cannot be matched at all",
    },
};

export function MatchStatePill(props: { state: WorkloadMatchState }) {
    const p = () => MATCH_PRESENTATION[props.state];
    return (
        <StatusPill variant={p().variant} title={p().title}>
            {p().label}
        </StatusPill>
    );
}
