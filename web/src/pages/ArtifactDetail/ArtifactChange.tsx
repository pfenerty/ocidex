import "./ArtifactChange.css";
import { For, Show, type JSX } from "solid-js";
import type { ArtifactVersionSummary } from "~/api/client";
import { formatDelta, sameVariantAsNewest, type SeverityPoint } from "~/utils/versionDelta";

/** The table's rows as severity points, newest first. */
export function severityPoints(versions: readonly ArtifactVersionSummary[] | undefined): SeverityPoint[] {
    return (versions ?? []).map((v) => ({
        versionKey: v.versionKey,
        arch: v.countedSbom?.architecture,
        critical: v.vulns?.critical,
        high: v.vulns?.high,
    }));
}

const W = 1000;
const H = 168;
const BASE = 128;
const TOP = 18;

/**
 * Critical findings per version of the newest version's variant, oldest on the
 * left, so every bar is compared with its own predecessor. Each bar is the version's
 * count; the block above it, hatched, is what the version fixed against the one
 * before; a solid amber block on top is what it added. Better and worse differ
 * in shape as well as colour, so the chart reads without colour.
 */
export function VersionChart(props: { points: SeverityPoint[] }): JSX.Element {
    const scanned = () => sameVariantAsNewest(props.points).reverse();
    const max = () => Math.max(1, ...scanned().map((p) => p.critical ?? 0));
    const k = () => (BASE - TOP) / max();
    const colW = () => W / Math.max(scanned().length, 1);
    const barW = () => Math.min(colW() * 0.42, 72);
    const label = () =>
        `Critical findings by version, oldest to newest: ${scanned()
            .map((p) => `${p.versionKey} ${p.critical ?? 0}`)
            .join(", ")}`;

    return (
        <Show when={scanned().length >= 2}>
            <figure class="version-chart">
                <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label()}>
                    <defs>
                        <pattern id="version-chart-hatch" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                            <line class="version-chart-hatch-line" x1="0" y1="0" x2="0" y2="5" />
                        </pattern>
                    </defs>
                    <line class="version-chart-axis" x1="0" y1={BASE + 0.5} x2={W} y2={BASE + 0.5} />
                    <For each={scanned()}>
                        {(p, i) => {
                            const cur = p.critical ?? 0;
                            const prev = () => (i() > 0 ? scanned()[i() - 1].critical ?? 0 : cur);
                            const x = () => i() * colW() + (colW() - barW()) / 2;
                            const cx = () => x() + barW() / 2;
                            const y = () => BASE - cur * k();
                            const yPrev = () => BASE - prev() * k();
                            const top = () => Math.min(y(), yPrev());
                            const d = () => cur - prev();
                            const latest = () => i() === scanned().length - 1;
                            return (
                                <g>
                                    <rect class="version-chart-bar" x={x()} y={y()} width={barW()} height={cur * k()} />
                                    <Show when={d() < 0}>
                                        <rect
                                            class="version-chart-fixed"
                                            x={x() + 0.5}
                                            y={yPrev() + 0.5}
                                            width={barW() - 1}
                                            height={Math.max(0, y() - yPrev() - 1)}
                                        />
                                    </Show>
                                    <Show when={d() > 0}>
                                        <rect class="version-chart-added" x={x()} y={y()} width={barW()} height={yPrev() - y()} />
                                    </Show>
                                    <text class="version-chart-count" x={cx()} y={top() - 6} text-anchor="middle">
                                        {cur.toLocaleString()}
                                        <Show when={i() > 0}>
                                            <tspan class="version-chart-delta" dx="6">
                                                {formatDelta(d())}
                                            </tspan>
                                        </Show>
                                    </text>
                                    <text
                                        class={`version-chart-version${latest() ? " latest" : ""}`}
                                        x={cx()}
                                        y={BASE + 18}
                                        text-anchor="middle"
                                    >
                                        {p.versionKey}
                                    </text>
                                </g>
                            );
                        }}
                    </For>
                </svg>
                <figcaption class="version-chart-legend">
                    <span><i class="swatch-critical" />critical</span>
                    <span><i class="swatch-fixed" />fixed since the previous version</span>
                    <span><i class="swatch-added" />added since the previous version</span>
                </figcaption>
            </figure>
        </Show>
    );
}
