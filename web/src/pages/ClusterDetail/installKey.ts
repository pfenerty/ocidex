import { createSignal } from "solid-js";

/**
 * The one-time key for a cluster's install command, held in memory only
 * (ocidex-70eo.6). The connect page mints it and navigates to the cluster;
 * the install card reads it from here. Never the URL, never storage: the key
 * is shown once, and a reload is the end of "once".
 */
export interface InstallKey {
    key: string;
    /** The API's configured public URL, when the server has one. */
    serverUrl?: string;
}

const [keys, setKeys] = createSignal<Record<string, InstallKey>>({});

export function installKeyFor(clusterId: string): InstallKey | undefined {
    return keys()[clusterId];
}

export function rememberInstallKey(clusterId: string, k: InstallKey): void {
    setKeys((prev) => ({ ...prev, [clusterId]: k }));
}

export function forgetInstallKey(clusterId: string): void {
    setKeys((prev) => {
        const next = { ...prev };
        delete next[clusterId];
        return next;
    });
}

/** The single helm command the connect flow hands out. */
export function helmInstallCommand(opts: { serverUrl: string; clusterId: string; key: string }): string {
    return [
        "helm install ocidex-k8s-agent oci://ghcr.io/pfenerty/charts/ocidex-k8s-agent \\",
        "  --namespace ocidex-agent --create-namespace \\",
        `  --set server.url=${opts.serverUrl} \\`,
        `  --set cluster.id=${opts.clusterId} \\`,
        `  --set apiKey.value=${opts.key}`,
    ].join("\n");
}

/**
 * The values.yaml form, for GitOps: it names a Secret rather than holding the
 * key, so the file can be committed. The Secret command comes with it.
 */
export function valuesYaml(opts: { serverUrl: string; clusterId: string }): string {
    return [
        "server:",
        `  url: ${opts.serverUrl}`,
        "cluster:",
        `  id: ${opts.clusterId}`,
        "apiKey:",
        "  # Create this Secret out of band (sealed-secrets, external-secrets, kubectl):",
        "  #   kubectl -n ocidex-agent create secret generic ocidex-k8s-agent-secrets \\",
        "  #     --from-literal=OCIDEX_API_KEY=<key>",
        "  secretName: ocidex-k8s-agent-secrets",
        "  secretKey: OCIDEX_API_KEY",
    ].join("\n");
}
