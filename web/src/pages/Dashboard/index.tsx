import { A } from "@solidjs/router";
import { createSignal, For, Show, type JSX } from "solid-js";
import { useAuth } from "~/context/auth";
import { useDiff, useMyMoves } from "~/api/queries";
import { PageHeader } from "~/components/ui";
import { QueryBoundary } from "~/components/ui/QueryBoundary";
import { Skeleton } from "~/components/Skeleton";
import { formatDate, plural } from "~/utils/format";
import { splitImageRef } from "~/utils/oci";
import type { components } from "~/types/openapi";
import { StatusFooter } from "./StatusFooter";
import "./Dashboard.css";

type Moves = NonNullable<ReturnType<typeof useMyMoves>["data"]>;
type Upgrade = Moves["upgrades"][number];
type LeftoverCritical = Moves["leftoverCriticals"][number];
type NamespaceMoves = Moves["namespaces"][number];
type CritHigh = components["schemas"]["CritHigh"];
type ComponentDiff = components["schemas"]["ComponentDiff"];

/** The waiting bar's full width, in days. Longer waits pin at full. */
export const WAIT_SCALE_DAYS = 60;

/** How many receipt rows an expanded upgrade shows before "N more". */
const RECEIPT_ROWS = 3;

/**
 * Dashboard is the signed-in Workspace: what the caller runs, what to move it
 * to, and what is left after. Everything above the footer reads one response,
 * /users/me/moves, so the KPI strip and the tables cannot disagree.
 */
export default function Dashboard(): JSX.Element {
    const { user } = useAuth();
    const moves = useMyMoves();

    return (
        <>
            <PageHeader
                title="Workspace"
                subtitle={
                    <Show when={user()} fallback="Your fleet and its upgrades">
                        {(u) => `Signed in as ${u().displayName}`}
                    </Show>
                }
            />
            <div class="ws">
                <QueryBoundary
                    query={moves}
                    loading={<Skeleton height="12rem" />}
                    empty={<p class="ws-empty">Nothing running or owned yet.</p>}
                    when={(m) => m.totals.images > 0}
                >
                    {(m) => (
                        <>
                            <KpiStrip moves={m()} />
                            <UpgradesTable moves={m()} />
                            <div class="ws-split">
                                <LeftoverTable rows={m().leftoverCriticals} />
                                <NamespaceTable rows={m().namespaces} source={m().source} />
                            </div>
                        </>
                    )}
                </QueryBoundary>
                <StatusFooter />
            </div>
        </>
    );
}

/** The image name with its registry and path muted, as Home shows it. */
function ImageName(props: { name: string }): JSX.Element {
    const parts = () => splitImageRef(props.name) ?? { prefix: "", name: props.name };
    return (
        <span class="ws-image" title={props.name}>
            <span class="ws-image-prefix">{parts().prefix}</span>
            <span class="ws-image-name">{parts().name}</span>
        </span>
    );
}

/** The last path segment of an image, for compact mentions. */
export function shortImage(name: string): string {
    return splitImageRef(name)?.name ?? name;
}

/** "a → b  −N" for one severity. */
function Delta(props: { before: number; after: number; tone: "critical" | "high" }): JSX.Element {
    const d = () => props.after - props.before;
    return (
        <span class="ws-delta">
            <span class="ws-muted">
                {props.before} → {props.after}
            </span>
            <span class={d() === 0 ? "ws-dim" : `ws-delta-${props.tone}`}>{d() === 0 ? "±0" : `−${-d()}`}</span>
        </span>
    );
}

function KpiStrip(props: { moves: Moves }): JSX.Element {
    const t = () => props.moves.totals;
    const cluster = () => props.moves.source === "cluster";
    return (
        <section class="ws-kpi" aria-label="Fleet summary">
            <div>
                <div class="ws-label">{cluster() ? "Running" : "Tracked"}</div>
                <div class="ws-kv">
                    {t().images}{" "}
                    <span class="ws-kv-sub">
                        {cluster() ? `images · ${plural(t().pods, "pod")}` : "images, newest owned tag"}
                    </span>
                </div>
            </div>
            <div>
                <div class="ws-label">Criticals {cluster() ? "running" : "now"}</div>
                <div class="ws-kv ws-critical">
                    {t().before.critical} <span class="ws-kv-sub">{t().after.critical} after upgrades</span>
                </div>
            </div>
            <div>
                <div class="ws-label">Highs {cluster() ? "running" : "now"}</div>
                <div class="ws-kv ws-high">
                    {t().before.high} <span class="ws-kv-sub">{t().after.high} after</span>
                </div>
            </div>
            <div>
                <div class="ws-label">Upgrades available</div>
                <div class="ws-kv">
                    {t().upgrades} <span class="ws-kv-sub">{t().upgradesCutCritical} cut criticals</span>
                </div>
            </div>
            <div>
                <div class="ws-label">Longest wait</div>
                <div class="ws-kv">
                    <Show when={t().upgrades > 0} fallback="—">
                        {t().longestWaitDays} d{" "}
                        <span class="ws-kv-sub">{shortImage(t().longestWaitImage ?? "")}</span>
                    </Show>
                </div>
            </div>
        </section>
    );
}

function WaitBar(props: { days: number; firstTag: string; firstDate: string }): JSX.Element {
    const pct = () => Math.min(100, Math.round((props.days / WAIT_SCALE_DAYS) * 100));
    return (
        <span class="ws-wait" title={`first better tag: ${props.firstTag} · ${formatDate(props.firstDate)}`}>
            <span class="ws-track">
                <span class="ws-age" style={{ width: `${pct()}%` }} />
            </span>
            <span class="ws-num ws-wait-days">{props.days} d</span>
        </span>
    );
}

function UpgradesTable(props: { moves: Moves }): JSX.Element {
    const total = (): { before: CritHigh; after: CritHigh; pods: number } => {
        const z = { before: { critical: 0, high: 0 }, after: { critical: 0, high: 0 }, pods: 0 };
        for (const u of props.moves.upgrades) {
            z.before.critical += u.before.critical;
            z.before.high += u.before.high;
            z.after.critical += u.after.critical;
            z.after.high += u.after.high;
            z.pods += u.pods;
        }
        return z;
    };
    return (
        <section class="ws-card" aria-label="Upgrades">
            <div class="ws-card-head">
                <h2>Upgrades</h2>
                <span class="ws-muted ws-small">
                    Sorted by days since a better tag shipped · bar scale {WAIT_SCALE_DAYS} d
                </span>
            </div>
            <Show
                when={props.moves.upgrades.length > 0}
                fallback={<p class="ws-empty">Everything is on its best available tag.</p>}
            >
                <div class="ws-up ws-up-head ws-label" aria-hidden="true">
                    <span>Image</span>
                    <span>Namespace</span>
                    <span class="ws-right">Pods</span>
                    <span>Running</span>
                    <span>Move to</span>
                    <span>Waiting</span>
                    <span class="ws-right">Critical</span>
                    <span class="ws-right">High</span>
                    <span />
                </div>
                <For each={props.moves.upgrades}>{(u) => <UpgradeRow upgrade={u} />}</For>
                <div class="ws-up ws-up-total">
                    <span>{plural(props.moves.upgrades.length, "image")}</span>
                    <span />
                    <span class="ws-num">{total().pods}</span>
                    <span />
                    <span />
                    <span />
                    <span class="ws-num">
                        <Delta before={total().before.critical} after={total().after.critical} tone="critical" />
                    </span>
                    <span class="ws-num">
                        <Delta before={total().before.high} after={total().after.high} tone="high" />
                    </span>
                    <span />
                </div>
            </Show>
        </section>
    );
}

function diffHref(u: Upgrade): string {
    return `/diff?from=${u.running.sbomId}&to=${u.target.sbomId}`;
}

function UpgradeRow(props: { upgrade: Upgrade }): JSX.Element {
    const [open, setOpen] = createSignal(false);
    const u = () => props.upgrade;
    return (
        <>
            <div class={open() ? "ws-up ws-up-row ws-up-open" : "ws-up ws-up-row"}>
                <button
                    type="button"
                    class="ws-expand"
                    aria-expanded={open()}
                    onClick={() => setOpen(!open())}
                >
                    <span class="ws-caret" aria-hidden="true">
                        {open() ? "▾" : "▸"}
                    </span>
                    <ImageName name={u().image} />
                </button>
                <span class="ws-muted ws-cell-ns">{u().namespaces.join(", ")}</span>
                <span class="ws-num">{u().pods}</span>
                <span class="ws-mono">{u().running.tag}</span>
                <span class="ws-mono">{u().target.tag}</span>
                <WaitBar days={u().waitingDays} firstTag={u().firstBetter.tag} firstDate={u().firstBetter.builtAt} />
                <span class="ws-num">
                    <Delta before={u().before.critical} after={u().after.critical} tone="critical" />
                </span>
                <span class="ws-num">
                    <Delta before={u().before.high} after={u().after.high} tone="high" />
                </span>
                <A href={diffHref(u())} class="ws-button">
                    Diff
                </A>
            </div>
            <Show when={open()}>
                <Receipt upgrade={u()} />
            </Show>
        </>
    );
}

/** Critical, high, medium closed by one change. */
function closeCounts(c: ComponentDiff): { critical: number; high: number; medium: number } {
    const out = { critical: 0, high: 0, medium: 0 };
    for (const v of c.closes ?? []) {
        if (v.severity === "CRITICAL") out.critical++;
        else if (v.severity === "HIGH") out.high++;
        else if (v.severity === "MEDIUM") out.medium++;
    }
    return out;
}

/** Changes that close a CVE, most criticals closed first, then most closed. */
export function receiptRows(changes: ComponentDiff[]): ComponentDiff[] {
    return changes
        .filter((c) => (c.closes ?? []).length > 0)
        .sort((a, b) => {
            const ca = closeCounts(a);
            const cb = closeCounts(b);
            if (ca.critical !== cb.critical) return cb.critical - ca.critical;
            return (b.closes ?? []).length - (a.closes ?? []).length;
        });
}

/**
 * Receipt is the expanded row: what moving from the running tag to the target
 * changes, read from the diff between the two, so a move across several
 * releases is one receipt rather than one per release. On a phone it also
 * carries the columns the collapsed row hides.
 */
function Receipt(props: { upgrade: Upgrade }): JSX.Element {
    const u = () => props.upgrade;
    const diff = useDiff(() => ({ from: u().running.sbomId, to: u().target.sbomId }));
    const rows = () => receiptRows(diff.data?.changes ?? []);
    const opens = () => (diff.data?.changes ?? []).filter((c) => (c.opens ?? []).length > 0);
    return (
        <div class="ws-receipt">
            <div class="ws-receipt-phone">
                <span>{u().namespaces.join(", ")}</span>
                <span>{plural(u().pods, "pod")}</span>
                <span class="ws-mono">
                    {u().running.tag} → {u().target.tag}
                </span>
                <span>
                    critical <Delta before={u().before.critical} after={u().after.critical} tone="critical" />
                </span>
                <span>
                    high <Delta before={u().before.high} after={u().after.high} tone="high" />
                </span>
                <A href={diffHref(u())}>Diff</A>
            </div>
            <QueryBoundary query={diff} loading={<Skeleton height="4rem" />}>
                {(d) => (
                    <>
                        <div class="ws-receipt-summary ws-muted">
                            <span>
                                first better tag <span class="ws-mono">{u().firstBetter.tag}</span>,{" "}
                                {formatDate(u().firstBetter.builtAt)}
                            </span>
                            <span>{plural(d().changes.length, "package change")}</span>
                            <span>{rows().length} close a CVE</span>
                            <Show when={opens().length > 0}>
                                <span>{opens().length} open one</span>
                            </Show>
                        </div>
                        <Show when={rows().length > 0}>
                            <div class="ws-rc ws-label">
                                <span>Package</span>
                                <span>Version</span>
                                <span>Closes</span>
                                <span>Criticals</span>
                            </div>
                            <For each={rows().slice(0, RECEIPT_ROWS)}>
                                {(c) => {
                                    const n = closeCounts(c);
                                    const crit = (c.closes ?? []).filter((v) => v.severity === "CRITICAL");
                                    return (
                                        <div class="ws-rc">
                                            <span class="ws-mono">{c.name}</span>
                                            <span class="ws-mono ws-muted">
                                                {c.previousVersion ?? "—"} → {c.version ?? "removed"}
                                            </span>
                                            <span class="ws-closes">
                                                <span class="ws-sw ws-sw-critical" />
                                                {n.critical}
                                                <span class="ws-sw ws-sw-high" />
                                                {n.high}
                                                <span class="ws-sw ws-sw-medium" />
                                                {n.medium}
                                            </span>
                                            <span class="ws-mono ws-muted ws-ellipsis">
                                                {crit
                                                    .slice(0, 2)
                                                    .map((v) => v.id)
                                                    .join(" · ")}
                                                {crit.length > 2 ? ` · +${crit.length - 2}` : ""}
                                            </span>
                                        </div>
                                    );
                                }}
                            </For>
                        </Show>
                        <div class="ws-receipt-foot ws-muted">
                            <Show when={rows().length > RECEIPT_ROWS}>
                                <span>{rows().length - RECEIPT_ROWS} more rows close CVEs · </span>
                            </Show>
                            <A href={`/artifacts/${u().artifactId}?tab=changelog`}>full changelog</A>
                            <Show when={u().alternative}>
                                {(alt) => (
                                    <span>
                                        {" "}
                                        · <span class="ws-mono">{alt().tag}</span> instead: criticals{" "}
                                        {alt().after.critical}, highs {alt().after.high}
                                    </span>
                                )}
                            </Show>
                        </div>
                    </>
                )}
            </QueryBoundary>
        </div>
    );
}

/** What the fix column says when no tag ships one. */
export function fixLabel(l: LeftoverCritical): string {
    if (l.fixedVersion !== undefined && l.fixedVersion !== "") return "upstream, no tag ships it yet";
    switch (l.fixState) {
        case "wont-fix":
            return "won't fix";
        case "not-fixed":
            return "no fix yet";
        default:
            return "no fix known";
    }
}

function LeftoverTable(props: { rows: LeftoverCritical[] }): JSX.Element {
    return (
        <section class="ws-card" aria-label="Criticals left after upgrades">
            <div class="ws-card-head">
                <h2>
                    Criticals left after upgrades <span class="ws-muted ws-normal">{props.rows.length}</span>
                </h2>
            </div>
            <Show when={props.rows.length > 0} fallback={<p class="ws-empty">None. Every critical has an upgrade.</p>}>
                <div class="ws-lc ws-label" aria-hidden="true">
                    <span>CVE</span>
                    <span class="ws-right">CVSS</span>
                    <span>Package</span>
                    <span>Fix</span>
                    <span>Images</span>
                </div>
                <For each={props.rows}>
                    {(l) => (
                        <div class="ws-lc">
                            <A class="ws-mono" href={`/vulnerabilities/${encodeURIComponent(l.id)}`}>
                                {l.id}
                            </A>
                            <span class="ws-num">{l.cvssScore?.toFixed(1) ?? "—"}</span>
                            <span class="ws-mono ws-ellipsis">
                                {l.package} {l.packageVersion}
                            </span>
                            <span>
                                <Show when={l.fixedVersion}>
                                    <span class="ws-mono">{l.fixedVersion}</span>{" "}
                                </Show>
                                <span class="ws-dim">{fixLabel(l)}</span>
                            </span>
                            <span class="ws-muted ws-ellipsis" title={l.images.join(", ")}>
                                {l.images.map(shortImage).join(", ")}{" "}
                                <span class="ws-num ws-strong">{l.images.length}</span>
                            </span>
                        </div>
                    )}
                </For>
            </Show>
        </section>
    );
}

function NamespaceTable(props: { rows: NamespaceMoves[]; source: Moves["source"] }): JSX.Element {
    return (
        <section class="ws-card" aria-label="By namespace">
            <div class="ws-card-head">
                <h2>By namespace</h2>
            </div>
            <div class="ws-ns ws-label" aria-hidden="true">
                <span>Namespace</span>
                <span class="ws-right">Imgs</span>
                <span class="ws-right">{props.source === "cluster" ? "Pods" : ""}</span>
                <span class="ws-right">Crit now → after</span>
                <span class="ws-right">High</span>
            </div>
            <For each={props.rows}>
                {(n) => (
                    <div class="ws-ns">
                        <span class="ws-ellipsis">{n.name}</span>
                        <span class="ws-num">{n.images}</span>
                        <span class="ws-num">{props.source === "cluster" ? n.pods : ""}</span>
                        <span class="ws-num">
                            {n.before.critical} → {n.after.critical}
                        </span>
                        <span class="ws-num ws-muted">
                            {n.before.high} → {n.after.high}
                        </span>
                    </div>
                )}
            </For>
        </section>
    );
}
