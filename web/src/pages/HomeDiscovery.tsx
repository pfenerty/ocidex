import { A } from "@solidjs/router";
import { Flame, Clock, ShieldAlert, Scale } from "lucide-solid";
import { For, Show, type JSX } from "solid-js";
import { Skeleton } from "~/components/Skeleton";
import { Badge, Card, QueryBoundary, TypeBadge } from "~/components/ui";
import { useDiscovery } from "~/api/queries";
import type { DiscoverVuln } from "~/api/queries";
import { plural } from "~/utils/format";

/** Severity drives the badge colour; anything unrecognised stays neutral. */
function severityVariant(severity: string): "danger" | "warning" | "default" {
    switch (severity.toUpperCase()) {
        case "CRITICAL":
        case "HIGH":
            return "danger";
        case "MEDIUM":
            return "warning";
        default:
            return "default";
    }
}

function relativeTime(iso: string | undefined): string {
    if (iso === undefined) return "";
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return "";
    const mins = Math.max(0, Math.round((Date.now() - then) / 60_000));
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.round(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.round(hours / 24)}d ago`;
}

/**
 * DiscoverPanel is the ADR-023 entry card wrapping one ranked list. The entry
 * number and the "see all" link are part of the field-guide identity: every
 * panel is an entry in the guide, and every entry has a fuller page behind it.
 */
function DiscoverPanel(props: {
    number: string;
    icon: JSX.Element;
    title: string;
    blurb: string;
    href: string;
    hrefLabel: string;
    children: JSX.Element;
}): JSX.Element {
    return (
        <Card as="section" class="entry-card landing-panel">
            <div class="landing-card-header">
                <span class="entry-number">{props.number}</span>
                <A href={props.href} class="landing-panel-all">
                    {props.hrefLabel}
                </A>
            </div>
            <h3 class="landing-card-title">
                {props.icon}
                {props.title}
            </h3>
            <p class="landing-card-desc">{props.blurb}</p>
            <ul class="landing-list">{props.children}</ul>
        </Card>
    );
}

/** A vulnerability's blast radius, in the unit a visitor can act on. */
function blastRadius(v: DiscoverVuln): string {
    return plural(v.affectedArtifactCount, "artifact");
}

/**
 * HomeDiscovery is the live half of the landing page: what the catalog actually
 * contains, ranked, instead of five cards describing what the catalog could
 * contain.
 *
 * Its three states stay visually distinct, the same rule the hero's stats band
 * follows. `warming` is a successful 200 whose sections are empty because the
 * server has not measured the catalog yet — rendering it as "nothing found"
 * would report an empty catalog, so it shares the loading treatment and the
 * query polls until a real snapshot lands.
 */
export function HomeDiscovery(): JSX.Element {
    const discovery = useDiscovery();

    // `warming` is a 200 with nothing measured yet, so it takes the loading
    // treatment rather than the empty one — hence the same block in both slots.
    const warmingOrLoading = (
        <div class="landing-discover-loading">
            <Skeleton width="100%" height="8rem" />
        </div>
    );

    return (
        <section class="landing-features">
            <QueryBoundary
                query={discovery}
                loading={warmingOrLoading}
                when={(d) => !d.warming}
                empty={warmingOrLoading}
                error={
                    <p class="text-muted landing-discover-error">
                        Catalog highlights are unavailable.
                    </p>
                }
            >
                    {(data) => (
                        <div class="landing-features-grid">
                            <DiscoverPanel
                                number="#001"
                                icon={<Flame size={16} class="landing-panel-icon" />}
                                title="Most depended on"
                                blurb="Artifacts other artifacts carry, ranked by how widely they appear and how recently they were seen."
                                href="/artifacts"
                                hrefLabel="all artifacts"
                            >
                                <For
                                    each={data().top_artifacts}
                                    fallback={
                                        <li class="landing-list-empty text-muted">
                                            Nothing indexed yet.
                                        </li>
                                    }
                                >
                                    {(a) => (
                                        <li class="landing-list-row">
                                            <A
                                                href={`/artifacts/${a.id}`}
                                                class="landing-list-name"
                                                title={a.purl ?? a.name}
                                            >
                                                {a.name}
                                            </A>
                                            <TypeBadge type={a.type} />
                                            <span class="landing-list-meta">
                                                {/* Usage is the ranking's dominant term, so it is
                                                    the figure shown; versions explain the rest of
                                                    the ordering when two are close. */}
                                                {plural(a.usageCount, "use")} ·{" "}
                                                {plural(a.versionCount, "version")}
                                            </span>
                                        </li>
                                    )}
                                </For>
                            </DiscoverPanel>

                            <DiscoverPanel
                                number="#002"
                                icon={<Clock size={16} class="landing-panel-icon" />}
                                title="Recently updated"
                                blurb="The newest SBOM for each artifact — one row per artifact, so a nightly rebuild cannot crowd out everything else."
                                href="/artifacts"
                                hrefLabel="all artifacts"
                            >
                                <For
                                    each={data().recent_artifacts}
                                    fallback={
                                        <li class="landing-list-empty text-muted">
                                            No recent activity.
                                        </li>
                                    }
                                >
                                    {(r) => (
                                        <li class="landing-list-row">
                                            <A
                                                href={`/artifacts/${r.artifactId}`}
                                                class="landing-list-name"
                                            >
                                                {r.name}
                                            </A>
                                            <Show when={r.subjectVersion}>
                                                {(v) => (
                                                    <Badge>
                                                        {v()}
                                                    </Badge>
                                                )}
                                            </Show>
                                            {/* Links to the SBOM that produced the
                                                timestamp, not just the artifact: the
                                                interesting thing about a recent row is
                                                the update itself. */}
                                            <A
                                                href={`/sboms/${r.sbomId}`}
                                                class="landing-list-meta landing-list-time"
                                            >
                                                {relativeTime(r.createdAt)}
                                            </A>
                                        </li>
                                    )}
                                </For>
                            </DiscoverPanel>

                            <DiscoverPanel
                                number="#003"
                                icon={<ShieldAlert size={16} class="landing-panel-icon" />}
                                title="Widest blast radius"
                                blurb="Vulnerabilities ranked by how many distinct artifacts carry an affected package — not by how many SBOMs, which every rescan inflates."
                                href="/vulnerabilities"
                                hrefLabel="all vulnerabilities"
                            >
                                <For
                                    each={data().top_vulnerabilities}
                                    fallback={
                                        <li class="landing-list-empty text-muted">
                                            No known vulnerabilities.
                                        </li>
                                    }
                                >
                                    {(v) => (
                                        <li class="landing-list-row">
                                            <A
                                                href={`/vulnerabilities/${encodeURIComponent(v.canonicalId)}`}
                                                class="landing-list-name"
                                                title={v.summary ?? v.canonicalId}
                                            >
                                                {v.canonicalId}
                                            </A>
                                            <Badge variant={severityVariant(v.severity)}>
                                                {v.severity.toLowerCase()}
                                            </Badge>
                                            <span class="landing-list-meta">{blastRadius(v)}</span>
                                        </li>
                                    )}
                                </For>
                            </DiscoverPanel>

                            <DiscoverPanel
                                number="#004"
                                icon={<Scale size={16} class="landing-panel-icon" />}
                                title="License spread"
                                blurb="Which licenses the catalog is actually made of, counted by distinct package identity rather than by SBOM row."
                                href="/licenses"
                                hrefLabel="all licenses"
                            >
                                <For
                                    each={data().license_spread}
                                    fallback={
                                        <li class="landing-list-empty text-muted">
                                            No licenses recorded.
                                        </li>
                                    }
                                >
                                    {(l) => (
                                        <li class="landing-list-row">
                                            <A
                                                href={`/licenses/${l.id}/components`}
                                                class="landing-list-name"
                                                title={l.name}
                                            >
                                                {l.spdxId ?? l.name}
                                            </A>
                                            <Badge>{l.category}</Badge>
                                            <span class="landing-list-meta">
                                                {plural(l.componentCount, "package")}
                                            </span>
                                        </li>
                                    )}
                                </For>
                            </DiscoverPanel>
                        </div>
                    )}
            </QueryBoundary>
        </section>
    );
}
