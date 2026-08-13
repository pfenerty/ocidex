import { Link2 } from "lucide-solid";
import { useToast } from "~/context/toast";
import { copyText } from "~/utils/clipboard";

interface CopyShareLinkProps {
    /** Resolver path with query string, e.g. /artifacts/lookup?name=myapp. */
    path: string;
    /** Button label; defaults to "Copy link". */
    label?: string;
    class?: string;
}

/**
 * Copies an ADR-042 resolver URL for the current record.
 *
 * ADR-042 accepts that the address bar shows the UUID once a resolver has
 * redirected, so copying from the address bar yields a link nobody can compose
 * or read. This control is the compensating affordance: it emits the
 * name-keyed form, absolutised against the current origin so the copied text is
 * pasteable anywhere.
 */
export default function CopyShareLink(props: CopyShareLinkProps) {
    const toast = useToast();

    const url = () => new URL(props.path, window.location.origin).toString();

    const copy = async () => {
        try {
            await copyText(url());
            toast("Shareable link copied", "success");
        } catch {
            toast("Failed to copy", "error");
        }
    };

    return (
        <button
            type="button"
            class={props.class ?? "btn btn-sm"}
            title={`Click to copy: ${url()}`}
            onClick={() => void copy()}
        >
            <Link2 size={14} />
            {props.label ?? "Copy link"}
        </button>
    );
}

/**
 * Resolver path for an artifact, carrying the full ADR-042 R4 ladder the record
 * has. Sending every rung we know is what makes the link resolve to one
 * candidate rather than 409 — the resolver treats an absent qualifier as a
 * wildcard, so omitting a known one only widens the match.
 */
export function artifactLookupPath(artifact: {
    name: string;
    type?: string;
    group?: string;
}): string {
    const params = new URLSearchParams({ name: artifact.name });
    if (artifact.type !== undefined && artifact.type !== "") {
        params.set("type", artifact.type);
    }
    if (artifact.group !== undefined && artifact.group !== "") {
        params.set("group", artifact.group);
    }
    return `/artifacts/lookup?${params.toString()}`;
}

/**
 * Resolver path for one SBOM, or null when the record carries no digest to key
 * on. Keyed on digest rather than the artifact+version ladder: a rebuild
 * produces a second SBOM with the same artifact, version, arch and flavor, so
 * the ladder form would start returning 409 for older links, whereas
 * sbom.digest is UNIQUE and pins this exact record forever.
 */
export function sbomLookupPath(sbom: { digest?: string }): string | null {
    if (sbom.digest === undefined || sbom.digest === "") return null;
    return `/sboms/lookup?${new URLSearchParams({ digest: sbom.digest }).toString()}`;
}
