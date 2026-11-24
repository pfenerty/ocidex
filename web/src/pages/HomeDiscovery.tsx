import { A } from "@solidjs/router";
import { For, Show, type JSX } from "solid-js";
import { Skeleton } from "~/components/Skeleton";
import { Card, QueryBoundary } from "~/components/ui";
import { useDashboardStats, useDiscovery } from "~/api/queries";
import type { DiscoverFeatured } from "~/api/queries";
import { formatDate } from "~/utils/format";
import { splitImageRef } from "~/utils/oci";
import { historyPoints, variantOf } from "~/utils/versionDelta";

type Discovery = NonNullable<ReturnType<typeof useDiscovery>["data"]>;
type DiscoverPackage = NonNullable<Discovery["topPackages"]>[number];
type DiscoverCut = NonNullable<Discovery["criticalCuts"]>[number];

/** The repository's last path segment in front, the registry path behind it. */
function ImageName(props: { name: string }): JSX.Element {
    const parts = () => splitImageRef(props.name) ?? { prefix: "", name: props.name };
    return (
        <span class="image-name">
            <span class="image-name-short">{parts().name}</span>
            <Show when={parts().prefix !== ""}>
                <span class="image-name-prefix">{parts().prefix.replace(/\/$/, "")}</span>
            </Show>
        </span>
    );
}

/**
 * The counted tag's line of the critical history, oldest first: same variant
 * and architecture as the newest point, scanned versions only. Mixing lines
 * would draw a Windows build's findings as a regression of the Debian one.
 */
export function criticalSeries(f: DiscoverFeatured): number[] {
    const points = historyPoints(f.criticalHistory);
    const head = points[0] as (typeof points)[number] | undefined;
    if (head === undefined) return [];
    const line = variantOf(head.versionKey);
    return points
        .filter((p) => variantOf(p.versionKey) === line && p.arch === head.arch && p.critical !== undefined)
        .map((p) => p.critical ?? 0)
        .reverse();
}

/** An inline sparkline. Coordinates come from the data, so it is drawn as SVG. */
function Sparkline(props: { values: number[] }): JSX.Element {
    const W = 96;
    const H = 20;
    const path = () => {
        const v = props.values;
        const max = Math.max(1, ...v);
        const step = v.length > 1 ? W / (v.length - 1) : 0;
        return v.map((y, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${(H - 2 - (y / max) * (H - 4)).toFixed(1)}`).join(" ");
    };
    return (
        <svg class="spark" viewBox={`0 0 ${W} ${H}`} width={W} height={H} aria-hidden="true">
            <path d={path()} />
        </svg>
    );
}

function totalCves(f: DiscoverFeatured): number {
    const v = f.vulns;
    return v.critical + v.high + v.medium + v.low + v.unknown;
}

const n = (x: number): string => x.toLocaleString();

function FeaturedTable(props: { rows: DiscoverFeatured[] }): JSX.Element {
    return (
        <Card as="section" class="home-card" aria-label="Images you've probably pulled">
            <div class="home-card-head">
                <h2>Images you've probably pulled</h2>
                <A href="/artifacts" class="home-all">
                    All artifacts →
                </A>
            </div>
            <div class="home-img home-label" aria-hidden="true">
                <span>Image</span>
                <span>Newest tag · built</span>
                <span class="home-right">Crit</span>
                <span class="home-right">High</span>
                <span class="home-right">All CVEs</span>
                <span>Criticals per tag, oldest → newest</span>
                <span class="home-right">Tags</span>
            </div>
            <For each={props.rows}>
                {(f) => {
                    const series = criticalSeries(f);
                    return (
                        <A href={`/artifacts/${f.artifactId}`} class="home-img home-row">
                            <ImageName name={f.name} />
                            <span class="home-mono home-ellipsis">
                                {f.subjectVersion ?? "—"}
                                <span class="home-muted home-date"> · {formatDate(f.builtAt ?? f.createdAt)}</span>
                            </span>
                            <span class={f.vulns.critical > 0 ? "home-num home-crit" : "home-num home-zero"}>
                                {n(f.vulns.critical)}
                            </span>
                            <span class={f.vulns.high > 0 ? "home-num home-high" : "home-num home-zero"}>
                                {n(f.vulns.high)}
                            </span>
                            <span class="home-num">
                                <Show when={f.vulnMatched || totalCves(f) > 0} fallback={<span class="home-muted">not scanned</span>}>
                                    {n(totalCves(f))}
                                </Show>
                            </span>
                            <span class="home-trend">
                                <Show when={series.length > 1} fallback={<span class="home-muted">one tag so far</span>}>
                                    <Sparkline values={series} />
                                    <span class="home-num home-muted">
                                        {series[0]} → {series[series.length - 1]}
                                    </span>
                                </Show>
                            </span>
                            <span class="home-num">{n(f.tagCount)}</span>
                        </A>
                    );
                }}
            </For>
            <p class="home-note">
                Counts are for the newest tag's preferred architecture. Criticals per tag are counted against today's CVE
                data, so older tags score worse as new CVEs land on them.
            </p>
        </Card>
    );
}

/** The Components list filtered to this package in its ecosystem. */
export function packageHref(p: DiscoverPackage): string {
    const q = new URLSearchParams({ name: p.name, purlType: p.ecosystem });
    if (p.group !== undefined) q.set("group", p.group);
    return `/components?${q.toString()}`;
}

function PackagesTable(props: { rows: DiscoverPackage[]; sbomCount?: number }): JSX.Element {
    const max = () => Math.max(1, ...props.rows.map((p) => p.sbomCount));
    return (
        <Card as="section" class="home-card" aria-label="Packages found in the most SBOMs">
            <div class="home-card-head">
                <h2>Packages found in the most SBOMs</h2>
                <A href="/components" class="home-all">
                    All packages →
                </A>
            </div>
            <p class="home-sub">
                <Show when={props.sbomCount}>{(c) => <>Out of {n(c())} SBOMs. </>}</Show>
                The most common package per ecosystem with a known critical or high.
            </p>
            <div class="home-pkg home-label" aria-hidden="true">
                <span>Package</span>
                <span>SBOMs</span>
                <span class="home-right">Vers</span>
                <span class="home-right">Crit / High</span>
            </div>
            <For each={props.rows}>
                {(p) => (
                    <A href={packageHref(p)} class="home-pkg home-row">
                        <span class="home-ellipsis">
                            <span class="home-mono home-strong">{p.name}</span>{" "}
                            <span class="home-muted home-eco">{p.ecosystem}</span>
                        </span>
                        <span class="home-bar-cell">
                            <span class="home-bar">
                                <span class="home-bar-fill" style={{ width: `${(p.sbomCount / max()) * 100}%` }} />
                            </span>
                            <span class="home-num">{n(p.sbomCount)}</span>
                        </span>
                        <span class="home-num">{n(p.versionCount)}</span>
                        <span class="home-num">
                            <span class={p.critical > 0 ? "home-crit" : "home-zero"}>{p.critical}</span>
                            <span class="home-muted"> / </span>
                            <span class={p.high > 0 ? "home-high" : "home-zero"}>{p.high}</span>
                        </span>
                    </A>
                )}
            </For>
        </Card>
    );
}

function CutsTable(props: { rows: DiscoverCut[] }): JSX.Element {
    return (
        <Card as="section" class="home-card" aria-label="Releases that cut criticals">
            <div class="home-card-head">
                <h2>Releases that cut criticals</h2>
                <span class="home-muted home-small">from each changelog</span>
            </div>
            <For each={props.rows}>
                {(c) => (
                    <A href={`/diff?from=${c.fromSbomId}&to=${c.toSbomId}`} class="home-cut home-row">
                        <ImageName name={c.name} />
                        <span class="home-mono home-ellipsis">
                            {c.fromVersion} → {c.toVersion}
                        </span>
                        <span class="home-num">
                            {c.fromCritical} → <span class={c.toCritical > 0 ? "home-crit" : ""}>{c.toCritical}</span>{" "}
                            <span class="home-muted">critical</span>
                        </span>
                        <span class="home-num home-muted">
                            {c.releasedAt !== undefined ? formatDate(c.releasedAt) : ""}
                        </span>
                    </A>
                )}
            </For>
        </Card>
    );
}

/**
 * HomeDiscovery is the data half of the landing page: things a visitor who
 * has never heard of OCIDex recognizes (images they pull, packages they ship),
 * as tables at body size. One response feeds all three, so they warm together.
 *
 * `warming` is a successful 200 whose sections are empty because the server
 * has not measured the catalog yet; it shares the loading treatment and the
 * query polls until a real snapshot lands.
 */
export function HomeDiscovery(): JSX.Element {
    const discovery = useDiscovery();
    const stats = useDashboardStats();
    const sbomCount = () => (stats.data && !stats.data.warming ? stats.data.sbomCount : undefined);

    const warmingOrLoading = (
        <div class="home-loading">
            <Skeleton width="100%" height="12rem" />
        </div>
    );

    return (
        <QueryBoundary
            query={discovery}
            loading={warmingOrLoading}
            when={(d) => !d.warming}
            empty={warmingOrLoading}
            error={<p class="home-muted home-error">Catalog highlights are unavailable.</p>}
        >
            {(data) => (
                <div class="home-tables">
                    <Show when={(data().featuredArtifacts ?? []).length > 0}>
                        <FeaturedTable rows={data().featuredArtifacts ?? []} />
                    </Show>
                    <div class="home-pair">
                        <Show when={(data().topPackages ?? []).length > 0}>
                            <PackagesTable rows={data().topPackages ?? []} sbomCount={sbomCount()} />
                        </Show>
                        <Show when={(data().criticalCuts ?? []).length > 0}>
                            <CutsTable rows={data().criticalCuts ?? []} />
                        </Show>
                    </div>
                </div>
            )}
        </QueryBoundary>
    );
}
