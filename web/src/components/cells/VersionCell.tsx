import { Match, Switch } from "solid-js";
import { Tooltip } from "~/components/ui";

/**
 * UNKNOWN_VERSION is the literal Syft writes when it can resolve a package but
 * not its version — Kubernetes staging modules are the common case, where the
 * binary carries a module path and a versionless purl. It is a statement about
 * the scan, not a version anyone released.
 *
 * Matched case-insensitively: the sentinel is a convention rather than a
 * format, and no real version is the word "unknown" in any casing.
 */
const UNKNOWN_VERSION = "unknown";

/**
 * VersionCell renders one package version, and distinguishes the two ways there
 * can fail to be one.
 *
 * Absent is an em dash: the SBOM says nothing. UNKNOWN is its own state,
 * because the SBOM does say something — that its producer looked and could not
 * tell — and printing that sentinel verbatim in a version column read as a
 * release actually named "UNKNOWN", sorted among the real ones.
 *
 * Every version column on the site goes through here.
 */
export function VersionCell(props: { version?: string }) {
    const normalized = () => (props.version ?? "").trim();
    const isUnknown = () => normalized().toLowerCase() === UNKNOWN_VERSION;

    return (
        <Switch fallback={<span class="text-muted">—</span>}>
            <Match when={isUnknown()}>
                <Tooltip content="The tool that produced this SBOM recorded no version for this package. Common for Go modules built from a source tree rather than a tagged release.">
                    <span class="text-muted text-sm">unknown</span>
                </Tooltip>
            </Match>
            <Match when={normalized() !== ""}>
                <span class="font-mono text-sm">{props.version}</span>
            </Match>
        </Switch>
    );
}
