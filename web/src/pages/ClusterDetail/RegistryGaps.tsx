import { For, Show } from "solid-js";
import { A } from "@solidjs/router";
import { Button, Card, CardHeader, StatusPill } from "~/components/ui";
import { plural } from "~/utils/format";
import type { UnknownHost } from "~/api/client";
import { REASON_PRESENTATION, addRegistryHref } from "./GapsTab";

/**
 * What to do about a host, and where that is done.
 *
 * Three different remedies, three different destinations: a host nothing is
 * configured for needs a registry created; one whose registry is switched off
 * needs it enabled; one excluded by patterns needs those widened. Collapsing
 * them into one "fix this" would send two thirds of readers to the wrong form.
 *
 * `repos` and `ns` only ride along on the create path. The edit paths open a
 * registry that already exists, and prefilling its Repositories from the gap
 * would silently propose replacing a configuration someone chose.
 *
 * `ns` is the cluster's own namespace, and it is what makes the create path
 * work at all: a cluster resolves images only against registries in its
 * namespace, and the API's default is to give a new registry a namespace of its
 * own. Without it this button reliably produced a registry the cluster could
 * not see, and the gap it promised to close stayed open.
 */
function remedyFor(host: UnknownHost, namespace: string): { label: string; href: string } {
    const repos = host.repositories ?? [];
    switch (host.reason) {
        case "registry_disabled":
            return { label: `Enable ${host.registry_name ?? "registry"}`, href: `/admin/sources?registry=${host.registry_id ?? ""}` };
        case "pattern_excluded":
            return { label: `Widen ${host.registry_name ?? "registry"} patterns`, href: `/admin/sources?registry=${host.registry_id ?? ""}` };
        default:
            return {
                label: "Add registry",
                href: addRegistryHref(host.host, repos, namespace),
            };
    }
}

/** One host: what it costs the cluster, what would close it, and the button. */
function HostRow(props: { host: UnknownHost; namespace: string }) {
    const remedy = () => remedyFor(props.host, props.namespace);
    const repos = () => props.host.repositories ?? [];
    const shown = () => repos().length;
    const total = () => props.host.repository_count;

    return (
        <li class="registry-gap-row">
            <div class="registry-gap-ident">
                <span class="font-mono registry-gap-host">{props.host.host}</span>
                <StatusPill variant={REASON_PRESENTATION[props.host.reason].variant}>
                    {REASON_PRESENTATION[props.host.reason].label}
                </StatusPill>
            </div>

            <div class="registry-gap-counts text-muted text-sm">
                {plural(props.host.image_count, "image")} ·{" "}
                {plural(props.host.pod_count, "pod")} ·{" "}
                {plural(total(), "repository", "repositories")}
            </div>

            {/* The repositories are shown, not merely counted: this is exactly
                what the button is about to write into the form, and a prefill a
                reader cannot see before clicking is a prefill they have to undo
                afterwards. */}
            <Show when={repos().length > 0}>
                <div class="registry-gap-repos font-mono text-sm text-muted">
                    <For each={repos()}>{(r) => <span>{r}</span>}</For>
                    {/* A capped list that reads as a complete one is the quiet
                        omission ADR-044 K5 exists to prevent. */}
                    <Show when={shown() < total()}>
                        <span class="registry-gap-more">
                            showing {shown().toLocaleString()} of {total().toLocaleString()}
                        </span>
                    </Show>
                </div>
            </Show>

            <Button as={A} href={remedy().href} size="sm" variant="primary" class="registry-gap-action">
                {remedy().label}
            </Button>
        </li>
    );
}

/**
 * RegistryGaps is the No-SBOM gap seen from the remedy's side.
 *
 * The table below it lists images, because an image is the unit of an ingest.
 * But the unit of *configuration* is a registry, and one registry closes every
 * row that names its host at once — twelve ghcr.io rows are one action, not
 * twelve. Without this card that has to be inferred from twelve identical links.
 *
 * The counts come from the server's rollup of the whole gap, never the page in
 * hand: a host's total taken off fifty rows would understate every cluster
 * bigger than one page, which is every cluster this card matters on.
 *
 * Hosts with nothing to configure — an image that is already ingestable, or a
 * reference carrying no host at all — are absent by construction: the server
 * groups only the three reasons that name a registry.
 */
export function RegistryGaps(props: { hosts: UnknownHost[]; namespace: string }) {
    const covered = () => props.hosts.reduce((n, h) => n + h.image_count, 0);

    return (
        <Show when={props.hosts.length > 0}>
            <Card class="mb-4">
                <CardHeader title="Registries to configure" count={props.hosts.length} />
                <p class="text-muted">
                    {plural(covered(), "image")} in this gap{" "}
                    {covered() === 1 ? "is" : "are"} waiting on{" "}
                    {plural(props.hosts.length, "registry", "registries")}. Configuring one closes
                    every image behind it at once.
                </p>
                <ul class="registry-gap-list">
                    <For each={props.hosts}>{(h) => <HostRow host={h} namespace={props.namespace} />}</For>
                </ul>
            </Card>
        </Show>
    );
}
