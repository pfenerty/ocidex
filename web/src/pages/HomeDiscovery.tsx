import { A } from "@solidjs/router";
import { Clock, Scale, ShieldAlert, Sparkles } from "lucide-solid";
import { For, Show, type JSX } from "solid-js";
import { Skeleton } from "~/components/Skeleton";
import { Badge, Card, QueryBoundary } from "~/components/ui";
import { SeverityPill, VulnCountBadges, severityColorClass } from "~/components/VulnBadge";
import { useDashboardStats, useDiscovery } from "~/api/queries";
import type { DiscoverFeatured, DiscoverRecent, DiscoverVuln } from "~/api/queries";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";
import { plural, relativeDate } from "~/utils/format";
import { splitImageRef } from "~/utils/oci";
import { StatusChip } from "~/components/ui";
import { VULN_DATA_STATUS } from "~/utils/status";

/** One slice of a MixBar: a count, the class that colours it and its label. */
interface MixSegment {
    key: string;
    count: number;
    class: string;
    label: string;
}

/**
 * A proportional stacked bar. Widths come from the data, so they go through
 * element.style at runtime (flex-grow), which the CSP allows; the colours are
 * classes, so both themes come from the stylesheet.
 */
function MixBar(props: { segments: MixSegment[]; label: string; thin?: boolean }): JSX.Element {
    const shown = () => props.segments.filter((s) => s.count > 0);
    const total = () => shown().reduce((n, s) => n + s.count, 0);
    const describe = () =>
        shown()
            .map((s) => `${s.count.toLocaleString()} ${s.label}`)
            .join(", ");
    return (
        <Show when={total() > 0}>
            <div
                class={`mix-bar${props.thin === true ? " mix-bar-thin" : ""}`}
                role="img"
                aria-label={`${props.label}: ${describe()}`}
                title={describe()}
            >
                <For each={shown()}>
                    {(s) => <span class={`mix-seg ${s.class}`} style={{ "flex-grow": String(s.count) }} />}
                </For>
            </div>
        </Show>
    );
}

function MixLegend(props: { segments: MixSegment[] }): JSX.Element {
    const total = () => props.segments.reduce((n, s) => n + s.count, 0);
    return (
        <ul class="mix-legend">
            <For each={props.segments.filter((s) => s.count > 0)}>
                {(s) => (
                    <li>
                        <span class={`mix-dot ${s.class}`} />
                        {s.label}
                        <span class="mix-legend-n">
                            {Math.round((s.count / total()) * 100)}%
                        </span>
                    </li>
                )}
            </For>
        </ul>
    );
}

const LICENSE_ORDER = ["permissive", "weak-copyleft", "copyleft", "uncategorized"] as const;

function licenseSegment(category: string, count: number): MixSegment {
    return {
        key: category,
        count,
        class: `lic-${category}`,
        label: (CATEGORY_COLORS[category]?.label ?? category).toLowerCase(),
    };
}

function featuredLicenseSegments(f: DiscoverFeatured): MixSegment[] {
    return [
        licenseSegment("permissive", f.licenses.permissive),
        licenseSegment("weak-copyleft", f.licenses.weakCopyleft),
        licenseSegment("copyleft", f.licenses.copyleft),
        licenseSegment("uncategorized", f.licenses.uncategorized),
    ];
}

function severitySegments(v: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
}): MixSegment[] {
    return [
        { key: "critical", count: v.critical, class: severityColorClass("CRITICAL"), label: "critical" },
        { key: "high", count: v.high, class: severityColorClass("HIGH"), label: "high" },
        { key: "medium", count: v.medium, class: severityColorClass("MEDIUM"), label: "medium" },
        { key: "low", count: v.low, class: severityColorClass("LOW"), label: "low" },
        { key: "unknown", count: v.unknown, class: severityColorClass(undefined), label: "unknown" },
    ];
}

/** The repository's last path segment in front, the registry path behind it. */
function ImageName(props: { name: string; class?: string }): JSX.Element {
    const parts = () => splitImageRef(props.name) ?? { prefix: "", name: props.name };
    return (
        <span class={`image-name ${props.class ?? ""}`}>
            <span class="image-name-short">{parts().name}</span>
            <Show when={parts().prefix !== ""}>
                <span class="image-name-prefix">{parts().prefix.replace(/\/$/, "")}</span>
            </Show>
        </span>
    );
}

function SectionHead(props: { icon: JSX.Element; title: string; href: string; hrefLabel: string }): JSX.Element {
    return (
        <div class="landing-section-head">
            <h2 class="landing-section-title">
                {props.icon}
                {props.title}
            </h2>
            <A href={props.href} class="landing-section-all">
                {props.hrefLabel} →
            </A>
        </div>
    );
}

function FeaturedCard(props: { item: DiscoverFeatured }): JSX.Element {
    const f = () => props.item;
    const vulnTotal = () =>
        f().vulns.critical + f().vulns.high + f().vulns.medium + f().vulns.low + f().vulns.unknown;
    return (
        <Card as="li" class="featured-card">
            <div class="featured-top">
                {/* The name is the card's one link; .featured-link::after
                    stretches it over the card so the whole tile is the target. */}
                <A href={`/artifacts/${f().artifactId}`} class="featured-link">
                    <ImageName name={f().name} class="featured-name" />
                </A>
                <Show when={f().subjectVersion}>{(v) => <Badge>{v()}</Badge>}</Show>
            </div>
            <dl class="featured-facts">
                <div>
                    <dt>Packages</dt>
                    <dd>{f().packageCount.toLocaleString()}</dd>
                </div>
                <div>
                    <dt>Vulnerabilities</dt>
                    <dd>
                        <Show when={vulnTotal() > 0} fallback={<StatusChip status={VULN_DATA_STATUS.clean} />}>
                            <VulnCountBadges
                                criticalCount={f().vulns.critical}
                                highCount={f().vulns.high}
                                mediumCount={f().vulns.medium}
                                lowCount={f().vulns.low}
                                unknownCount={f().vulns.unknown}
                            />
                        </Show>
                    </dd>
                </div>
            </dl>
            <MixBar thin label="Licenses" segments={featuredLicenseSegments(f())} />
            <p class="featured-updated">updated {relativeDate(f().createdAt)}</p>
        </Card>
    );
}

function VulnRow(props: { v: DiscoverVuln }): JSX.Element {
    return (
        <li class="landing-row">
            <div class="landing-row-main">
                <A
                    href={`/vulnerabilities/${encodeURIComponent(props.v.canonicalId)}`}
                    class="landing-row-name landing-mono"
                >
                    {props.v.canonicalId}
                </A>
                <SeverityPill severity={props.v.severity}>{props.v.severity.toLowerCase()}</SeverityPill>
                <span class="landing-row-meta">{plural(props.v.affectedArtifactCount, "artifact")}</span>
            </div>
            <Show when={props.v.summary}>{(s) => <p class="landing-row-sub">{s()}</p>}</Show>
        </li>
    );
}

function RecentRow(props: { r: DiscoverRecent }): JSX.Element {
    return (
        <li class="recent-row">
            <A href={`/artifacts/${props.r.artifactId}`} class="recent-name">
                <ImageName name={props.r.name} />
            </A>
            <Show when={props.r.subjectVersion}>
                {(v) => <span class="recent-version landing-mono">{v()}</span>}
            </Show>
            <A href={`/sboms/${props.r.sbomId}`} class="recent-time">
                {relativeDate(props.r.createdAt)}
            </A>
        </li>
    );
}

/**
 * HomeDiscovery is the live half of the landing page: what the catalog holds,
 * shown rather than listed (ocidex-gu40). Featured images lead because they are
 * the names a visitor recognises; the exposure and license panels summarise the
 * whole catalog as proportions before naming its top entries.
 *
 * Its three states stay visually distinct, the same rule the hero's stats band
 * follows. `warming` is a successful 200 whose sections are empty because the
 * server has not measured the catalog yet, so it shares the loading treatment
 * and the query polls until a real snapshot lands.
 */
export function HomeDiscovery(): JSX.Element {
    const discovery = useDiscovery();
    // Same query (and cache entry) as the hero's stat band. The catalog-wide
    // severity and license mixes live there; they stay optional, because a
    // warming or failed stats call must not take the discovery panels with it.
    const stats = useDashboardStats();
    const warmStats = () => (stats.data && !stats.data.warming ? stats.data : undefined);

    const severityMix = () => {
        const s = warmStats()?.vulnSeverity;
        return s === undefined ? [] : severitySegments(s);
    };
    const licenseMix = () => {
        const cats = warmStats()?.licenseCategories ?? [];
        const by = new Map(cats.map((c) => [c.category, c.componentCount]));
        return LICENSE_ORDER.map((c) => licenseSegment(c, by.get(c) ?? 0));
    };

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
                error={<p class="text-muted landing-discover-error">Catalog highlights are unavailable.</p>}
            >
                {(data) => (
                    <div class="landing-features-grid">
                        <Show when={(data().featuredArtifacts ?? []).length > 0}>
                            <section class="landing-section">
                                <SectionHead
                                    icon={<Sparkles size={16} />}
                                    title="Featured images"
                                    href="/artifacts"
                                    hrefLabel="All artifacts"
                                />
                                <ul class="featured-grid">
                                    <For each={data().featuredArtifacts}>
                                        {(f) => <FeaturedCard item={f} />}
                                    </For>
                                </ul>
                            </section>
                        </Show>

                        <div class="landing-pair">
                            <Card as="section" class="landing-panel">
                                <SectionHead
                                    icon={<ShieldAlert size={16} />}
                                    title="Vulnerability exposure"
                                    href="/vulnerabilities"
                                    hrefLabel="All vulnerabilities"
                                />
                                <MixBar label="Known vulnerabilities by severity" segments={severityMix()} />
                                <MixLegend segments={severityMix()} />
                                <h3 class="landing-subhead">Widest blast radius</h3>
                                <ul class="landing-list">
                                    <For
                                        each={data().topVulnerabilities}
                                        fallback={<li class="landing-list-empty text-muted">No known vulnerabilities.</li>}
                                    >
                                        {(v) => <VulnRow v={v} />}
                                    </For>
                                </ul>
                            </Card>

                            <Card as="section" class="landing-panel">
                                <SectionHead
                                    icon={<Scale size={16} />}
                                    title="License mix"
                                    href="/licenses"
                                    hrefLabel="All licenses"
                                />
                                <MixBar label="Packages by license category" segments={licenseMix()} />
                                <MixLegend segments={licenseMix()} />
                                <h3 class="landing-subhead">Most common licenses</h3>
                                <ul class="landing-list">
                                    <For
                                        each={data().licenseSpread}
                                        fallback={<li class="landing-list-empty text-muted">No licenses recorded.</li>}
                                    >
                                        {(l) => (
                                            <li class="landing-row">
                                                <div class="landing-row-main">
                                                    <span class={`mix-dot lic-${l.category}`} />
                                                    <A
                                                        href={`/licenses/${l.id}/components`}
                                                        class="landing-row-name"
                                                        title={l.name}
                                                    >
                                                        {l.spdxId ?? l.name}
                                                    </A>
                                                    <span class="landing-row-meta">
                                                        {plural(l.componentCount, "package")}
                                                    </span>
                                                </div>
                                            </li>
                                        )}
                                    </For>
                                </ul>
                            </Card>
                        </div>

                        <Card as="section" class="landing-panel">
                            <SectionHead
                                icon={<Clock size={16} />}
                                title="Recently updated"
                                href="/artifacts"
                                hrefLabel="All artifacts"
                            />
                            <ul class="recent-grid">
                                <For
                                    each={data().recentArtifacts}
                                    fallback={<li class="landing-list-empty text-muted">Nothing indexed yet.</li>}
                                >
                                    {(r) => <RecentRow r={r} />}
                                </For>
                            </ul>
                        </Card>
                    </div>
                )}
            </QueryBoundary>
        </section>
    );
}
