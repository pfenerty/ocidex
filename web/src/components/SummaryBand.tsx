import type { OCIMetadata, Provenance, GitCommitMetadata, VulnSummary } from "~/api/client";
import { relativeDate } from "~/utils/format";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { StatBand, type StatTile } from "./ui/StatBand";
import { vulnTile } from "./VulnTile";
import { ShieldIcon, OciIcon, ContainerIcon, GitHubIcon } from "./metadata/OciIcons";

export type SbomTab = "packages" | "provenance" | "image" | "git" | "vulns" | "raw";

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
        // This band is the one place the vulnerability count is scoped to a
        // single SBOM; the artifact and component bands share the tile and
        // count over wider sets (ocidex-7gf7.7).
        vulnTile<SbomTab>(props.vulns, "vulns", "this SBOM"),
        {
            id: "raw",
            head: "SBOM",
            value: `CycloneDX ${props.specVersion}`,
            sub: `ingested ${relativeDate(props.ingestedAt)}`,
        },
    ];

    return <StatBand tiles={tiles()} active={props.active} onSelect={props.onSelect} />;
}
