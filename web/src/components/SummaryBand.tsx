import { Show } from "solid-js";
import type { OCIMetadata, Provenance, GitCommitMetadata, VulnSummary } from "~/api/client";
import { relativeDate } from "~/utils/format";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { StatBand, type StatTile } from "./ui/StatBand";
import { SeverityPill } from "./VulnBadge";
import { ShieldIcon, OciIcon, ContainerIcon, GitHubIcon } from "./metadata/OciIcons";

export type SbomTab = "packages" | "provenance" | "image" | "git" | "raw";

// shortBuilder renders a recognizable builder name from a SLSA builder id URL.
function shortBuilder(id: string | undefined): string | undefined {
    if (id === undefined || id === "") return undefined;
    if (id.includes("tekton")) return "Tekton Chains";
    if (id.includes("github")) return "GitHub Actions";
    return id.replace(/^https?:\/\//, "");
}

// provenanceSubline captions the provenance tile. It names the build that
// produced the artifact when the attestation carries a builder id, and
// otherwise falls back to the signing material that is actually present.
//
// It must never claim material is absent that the enrichment recorded as
// present: this line previously printed "no signature" whenever `builderId`
// was unset, so a signed artifact without build metadata read
// "Signed / no signature".
function provenanceSubline(p: Provenance | undefined): string {
    if (p === undefined) return "—";

    const builder = shortBuilder(p.builderId);
    if (builder !== undefined) return builder;

    const facts = [
        p.signaturePresent === true ? "cosign signature" : undefined,
        p.attestationPresent === true ? "SLSA attestation" : undefined,
    ].filter((f) => f !== undefined);

    return facts.length > 0 ? facts.join(" · ") : "no signing material";
}

// VulnTileSub captions the vulnerability tile. "no known vulnerabilities" is a
// claim about what has been scanned, so it is only made when a summary exists —
// an SBOM that was never scanned says so instead of reading as clean, which is
// the same distinction ADR-044 insists on for unmatched cluster workloads.
function VulnTileSub(props: {
    vulns: VulnSummary | undefined;
    worst: { label: string; count: number } | undefined;
}) {
    return (
        <Show when={props.vulns !== undefined} fallback={<>not scanned</>}>
            <Show when={props.worst} fallback={<>no known vulnerabilities</>}>
                {(w) => (
                    <SeverityPill severity={w().label}>
                        {w().count} {w().label}
                    </SeverityPill>
                )}
            </Show>
        </Show>
    );
}

export default function SummaryBand(props: {
    provenance: Provenance | undefined;
    signingStatus: string | undefined;
    metadata: OCIMetadata | undefined;
    git: GitCommitMetadata | undefined;
    packageCount: number | undefined;
    ecosystems: string[];
    vulns: VulnSummary | undefined;
    specVersion: string;
    ingestedAt: string;
    active: SbomTab;
    onSelect: (tab: SbomTab) => void;
}) {
    const trust = () => trustStatus(props.signingStatus);
    const platform = () => {
        const m = props.metadata;
        if (m === undefined) return undefined;
        const p = [m.os, m.architecture].filter(Boolean).join("/");
        return p === "" ? undefined : p;
    };

    // The worst severity present, which is the figure that decides whether this
    // SBOM needs attention. A bare total flattens "1 critical" into the same
    // shape as "40 low".
    const worstSeverity = (): { label: string; count: number } | undefined => {
        const v = props.vulns;
        if (v === undefined) return undefined;
        const ranked = [
            { label: "critical", count: v.critical },
            { label: "high", count: v.high },
            { label: "medium", count: v.medium },
            { label: "low", count: v.low },
            { label: "unknown", count: v.unknown },
        ];
        return ranked.find((r) => r.count > 0);
    };

    const tiles = (): StatTile<SbomTab>[] => [
        {
            id: "provenance",
            icon: <ShieldIcon />,
            head: "Provenance",
            // trustStatus returns null, not undefined, for an unenriched SBOM.
            value: trust()?.label ?? "Not enriched",
            valueClass: (() => {
                const t = trust();
                return t !== null ? trustBadgeClass(t.variant) : "text-muted";
            })(),
            sub: provenanceSubline(props.provenance),
        },
        {
            id: "image",
            icon: <OciIcon />,
            head: "Image",
            value: platform() ?? "\u2014",
            sub:
                props.metadata?.baseName !== undefined && props.metadata.baseName !== "" ? (
                    <>
                        <ContainerIcon /> {props.metadata.baseName}
                    </>
                ) : (
                    "OCI image"
                ),
        },
        {
            id: "git",
            icon: <GitHubIcon />,
            head: "Git",
            value:
                props.git?.resolved === true
                    ? (props.git.commitSha?.substring(0, 8) ?? "\u2014")
                    : "\u2014",
            sub:
                props.git?.resolved === true
                    ? `${props.git.owner}/${props.git.repo}`
                    : "not enriched",
        },
        {
            id: "packages",
            head: "Packages",
            value: props.packageCount ?? "\u2014",
            sub: props.ecosystems.length > 0 ? props.ecosystems.join(" \u00b7 ") : "components",
        },
        // Not selectable: the page has no vulnerabilities tab yet, and a tile
        // that looks like a button but does nothing is worse than a plain stat.
        // ocidex-ag4q.34 gives it a destination.
        {
            head: "Vulnerabilities",
            value: props.vulns?.total ?? "\u2014",
            // The severity signal is a SeverityPill in the sub-line rather than a
            // colour on the number: the shared redscale (`sev-*`) is a set of
            // badge *backgrounds*, so applying it to `.tile-value` would paint a
            // full-bleed block behind the count instead of tinting it.
            sub: <VulnTileSub vulns={props.vulns} worst={worstSeverity()} />,
        },
        {
            id: "raw",
            head: "SBOM",
            value: `CycloneDX ${props.specVersion}`,
            sub: `ingested ${relativeDate(props.ingestedAt)}`,
        },
    ];

    return <StatBand tiles={tiles()} active={props.active} onSelect={props.onSelect} />;
}
