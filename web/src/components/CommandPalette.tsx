import "./CommandPalette.css";
import {
    For,
    Show,
    createEffect,
    createMemo,
    createSignal,
    createUniqueId,
    onCleanup,
} from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Search } from "lucide-solid";
import { useAuth } from "~/context/auth";
import { artifactLookupPath, sbomLookupPath } from "~/components/CopyShareLink";
import {
    useArtifactSearch,
    useComponentSearch,
    useVulnerabilitySearch,
    useLicenseSearch,
    MIN_SEARCH_TERM,
} from "~/api/queries";
import type { SearchHit } from "~/api/queries";

interface User {
    role: string;
}

interface Entry {
    path: string;
    label: string;
    group: string;
    /** Extra words the entry should answer to. Never rendered. */
    keywords?: string;
    /** Omit for entries anyone may reach. */
    visible?: (user: User | undefined) => boolean;
}

const signedIn = (u: User | undefined): boolean => u !== undefined;
const isAdmin = (u: User | undefined): boolean => u?.role === "admin";

/**
 * Every destination in the app that can be reached without an id.
 *
 * Deliberately hand-written rather than derived from `App.tsx`: more than half
 * of those routes take a `:id` and are not destinations at all, two are ADR-042
 * resolvers, and the ones that remain need a human-readable name and search
 * words that no route table carries.
 *
 * `visible` mirrors the sidebar's rules in `Layout.tsx` — offering "Workspace"
 * to a signed-out visitor would navigate them straight into a redirect back to
 * /login, which is a worse answer than not offering it at all.
 */
const ENTRIES: readonly Entry[] = [
    { path: "/", label: "Home", group: "Explore", keywords: "start landing overview" },
    { path: "/artifacts", label: "Artifacts", group: "Explore", keywords: "images oci containers sboms" },
    { path: "/components", label: "Components", group: "Explore", keywords: "packages dependencies purl" },
    { path: "/components/overview", label: "Component versions", group: "Explore", keywords: "spread versions rollup" },
    { path: "/licenses", label: "Licenses", group: "Explore", keywords: "spdx compliance legal" },
    { path: "/vulnerabilities", label: "Vulnerabilities", group: "Explore", keywords: "cve cves vulns security advisories osv" },
    { path: "/diff", label: "Compare", group: "Explore", keywords: "diff changelog drift versions" },

    { path: "/dashboard", label: "Workspace", group: "Workspace", keywords: "dashboard mine watched", visible: signedIn },
    { path: "/clusters", label: "Clusters", group: "Workspace", keywords: "kubernetes k8s workloads inventory coverage", visible: signedIn },

    // Sources sits under /admin for historical reasons only — any signed-in
    // user may manage the registries they own. See the note in Layout.tsx.
    { path: "/admin/sources", label: "Sources", group: "Manage", keywords: "registries ingest scan", visible: signedIn },
    { path: "/admin/keys", label: "API keys", group: "Manage", keywords: "tokens credentials scopes", visible: isAdmin },
    { path: "/admin/namespaces", label: "Namespaces", group: "Manage", keywords: "owners visibility tenants", visible: isAdmin },
    { path: "/admin/status", label: "Status", group: "Manage", keywords: "health workers queue", visible: isAdmin },
    { path: "/admin/jobs", label: "Jobs", group: "Manage", keywords: "scan enrichment queue failures", visible: isAdmin },

    { path: "/login", label: "Sign in", group: "Account", keywords: "github login auth", visible: (u) => u === undefined },
];

/** How long a keystroke waits before it costs a request. */
const SEARCH_DEBOUNCE_MS = 300;

const LOOKUP_GROUP = "Look up";

/** sha256:<64 hex>, or the bare hex a registry UI copies without the prefix. */
const DIGEST_RE = /^(sha256:)?[0-9a-f]{64}$/i;

/** One rendered row, whether it came from the route list or from the catalog. */
interface Row {
    key: string;
    label: string;
    /** Right-hand qualifier: a route's path, or a hit's type/severity/version count. */
    sub?: string;
    path: string;
    group: string;
}

/**
 * The ADR-042 resolver rows.
 *
 * The catalog hits above already carry an id, so they navigate straight to it —
 * sending a row the user has *already* disambiguated back through a name lookup
 * would only hand them a 409 for their trouble. What the resolvers are for is
 * the other case: the user knows the exact name, digest or purl and wants the
 * canonical, shareable URL. `App.tsx` has routed /artifacts/lookup and
 * /sboms/lookup since ADR-042 landed and nothing in the UI ever linked to them;
 * this is the link.
 *
 * The key travels in query params, never a path segment — artifact names carry
 * slashes, so `by-name/{name}` is not viable (ADR-042). A 409 lands on
 * `pages/Lookup.tsx`, which renders the returned candidates as a list to pick
 * from rather than an error.
 *
 * Components are excluded from the resolvers (they are SBOM-scoped), so a purl
 * goes to the occurrence list at /components?purl= instead, per the same ADR.
 */
function lookupRows(term: string): Row[] {
    const row = (key: string, label: string, path: string): Row[] => [
        { key: `lookup:${key}`, label, sub: path, path, group: LOOKUP_GROUP },
    ];
    if (term.length < MIN_SEARCH_TERM) return [];
    if (DIGEST_RE.test(term)) {
        // Registry UIs copy the hex with and without the algorithm prefix; the
        // resolver wants the whole digest.
        const digest = term.startsWith("sha256:") ? term : `sha256:${term}`;
        const path = sbomLookupPath({ digest });
        return path === null ? [] : row("sbom", "Resolve SBOM by digest", path);
    }
    if (term.startsWith("pkg:")) {
        const purl = new URLSearchParams({ purl: term }).toString();
        return row("purl", `Every SBOM carrying ${term}`, `/components?${purl}`);
    }
    // The same builders the copy-link control uses, so a palette link and a
    // copied link are the same URL.
    return row("artifact", `Resolve artifact "${term}"`, artifactLookupPath({ name: term }));
}

// Module scope so anything can raise the palette without threading state
// through the tree — `Layout.tsx`'s sidebar trigger is the only caller today,
// but a palette nobody can find is worth nothing, and every future affordance
// wants the same door.
const [open, setOpen] = createSignal(false);

/** Raise the palette. Safe to call while it is already open. */
export function openCommandPalette(): void {
    setOpen(true);
}

/** True on Apple platforms, where the shortcut reads as Cmd-K rather than Ctrl-K. */
export function isAppleShortcut(): boolean {
    return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);
}

/**
 * A two-keystroke route to anywhere in the app.
 *
 * Mounted once, in `Layout.tsx`, and outside the `/login` branch — the shortcut
 * is muscle memory or it is nothing, so it may not blink out on one route.
 *
 * Two kinds of row share one list. The route entries above are filtered
 * synchronously — they are already in memory, so a debounce there would only add
 * lag between a keystroke and the list narrowing. Catalog results fan out to
 * four endpoints and so are debounced by `SEARCH_DEBOUNCE_MS`, and they arrive
 * *beside* the route entries rather than replacing them: "vulnerabilities" must
 * still offer the page even once it also offers matching CVEs.
 *
 * A group that errors is rendered as absent. For a signed-out visitor a 401 from
 * any one endpoint is an answer about what they may see, not a failure of the
 * palette — and since ocidex-ag4q.1 it no longer navigates anywhere.
 */
export default function CommandPalette() {
    const navigate = useNavigate();
    const { user } = useAuth();
    const listId = createUniqueId();

    let dialogEl: HTMLDialogElement | undefined;
    let listEl: HTMLUListElement | undefined;
    let inputEl: HTMLInputElement | undefined;

    const [query, setQuery] = createSignal("");
    const [highlight, setHighlight] = createSignal(0);

    // A freshly mounted palette is shut, whatever a previous instance left in
    // the module-level signal. The app mounts exactly one, so this only ever
    // matters to tests — but it is what makes sharing that signal safe.
    setOpen(false);

    const available = createMemo(() =>
        ENTRIES.filter((e) => e.visible === undefined || e.visible(user())),
    );

    const routeMatches = createMemo(() => {
        const terms = query().toLowerCase().split(/\s+/).filter((t) => t !== "");
        if (terms.length === 0) return available();
        return available().filter((e) => {
            const hay = `${e.label} ${e.group} ${e.path} ${e.keywords ?? ""}`.toLowerCase();
            return terms.every((t) => hay.includes(t));
        });
    });

    // The debounce delays the *request*, never the displayed value: `query`
    // drives the box and the route filter, `debounced` drives the four fetches.
    const [debounced, setDebounced] = createSignal("");
    let debounceTimer: ReturnType<typeof setTimeout> | undefined;
    createEffect(() => {
        const q = query().trim();
        if (debounceTimer !== undefined) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => setDebounced(q), SEARCH_DEBOUNCE_MS);
    });
    onCleanup(() => {
        if (debounceTimer !== undefined) clearTimeout(debounceTimer);
    });

    const artifacts = useArtifactSearch(debounced);
    const components = useComponentSearch(debounced);
    const vulns = useVulnerabilitySearch(debounced);
    const licenses = useLicenseSearch(debounced);

    const searches = [
        { group: "Artifacts", query: artifacts },
        { group: "Components", query: components },
        { group: "Vulnerabilities", query: vulns },
        { group: "Licenses", query: licenses },
    ];

    /** True once a term is long enough to have been sent. */
    const searchable = (): boolean => debounced().length >= MIN_SEARCH_TERM;

    /** A keystroke is in the debounce window, or a fetch is in flight. */
    const searching = (): boolean =>
        query().trim() !== debounced() || (searchable() && searches.some((s) => s.query.isFetching));

    const rows = createMemo<Row[]>(() => {
        const out: Row[] = routeMatches().map((e) => ({
            key: e.path,
            label: e.label,
            sub: e.path,
            path: e.path,
            group: e.group,
        }));
        // `keepPreviousData` deliberately outlives the query that fetched it, so
        // the rows do not blink between keystrokes — which also means the last
        // term's hits are still in `data` after the box is cleared. Gate on the
        // live term rather than on the cache.
        if (searchable()) {
            for (const s of searches) {
                // An errored group contributes nothing rather than an error row:
                // the palette is a way to get somewhere, not a place to report
                // failures.
                const hits: SearchHit[] | undefined = s.query.isError ? undefined : s.query.data;
                for (const h of hits ?? []) {
                    out.push({ key: `${s.group}:${h.key}`, label: h.label, sub: h.sub, path: h.path, group: s.group });
                }
            }
        }
        // Last, and off the live term rather than the debounced one: no request
        // stands behind it, so there is nothing to wait for. It is the fallback
        // when the search groups came back empty, and in that case it is the
        // only row and therefore already highlighted.
        out.push(...lookupRows(query().trim()));
        return out;
    });

    // The resolver rows are always on offer, so they are not evidence that
    // anything matched — a term nothing knows about still gets a "Resolve
    // artifact" row, and it would read as a hit if the empty line vanished
    // with it.
    const nothingMatched = (): boolean => rows().every((r) => r.group === LOOKUP_GROUP);

    // Groups are derived from the filtered list rather than filtered per group,
    // so a group that matches nothing disappears instead of leaving a heading
    // over empty space. The flat index rides along because the highlight is
    // flat — arrow keys cross group boundaries without the user noticing them.
    const groups = createMemo(() => {
        const out: { name: string; items: { row: Row; index: number }[] }[] = [];
        rows().forEach((row, index) => {
            let g = out.find((o) => o.name === row.group);
            if (g === undefined) {
                g = { name: row.group, items: [] };
                out.push(g);
            }
            g.items.push({ row, index });
        });
        return out;
    });

    function close(): void {
        setOpen(false);
        dialogEl?.close();
        setQuery("");
        setDebounced("");
        setHighlight(0);
    }

    function choose(row: Row): void {
        close();
        navigate(row.path);
    }

    // The dialog is imperative — `showModal()` is what puts it in the top layer
    // and traps focus — so the signal drives the element rather than the markup.
    createEffect(() => {
        const el = dialogEl;
        if (el === undefined) return;
        if (open()) {
            if (!el.open) el.showModal();
            inputEl?.focus();
        } else if (el.open) {
            el.close();
        }
    });

    // Keep the highlighted row on screen when the arrow keys walk past the fold.
    createEffect(() => {
        const i = highlight();
        const el = listEl?.querySelectorAll("[role='option']")[i];
        el?.scrollIntoView({ block: "nearest" });
    });

    function onDocumentKeyDown(e: KeyboardEvent): void {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            if (open()) close();
            else setOpen(true);
            return;
        }
        // A real browser closes the dialog on Escape by itself; this keeps our
        // own state in step with it, and is the only path in a test DOM.
        if (e.key === "Escape" && open()) close();
    }

    document.addEventListener("keydown", onDocumentKeyDown);
    onCleanup(() => document.removeEventListener("keydown", onDocumentKeyDown));

    function onKeyDown(e: KeyboardEvent): void {
        const list = rows();
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            if (list.length === 0) return;
            const step = e.key === "ArrowDown" ? 1 : -1;
            setHighlight((h) => (h + step + list.length) % list.length);
            return;
        }
        if (e.key === "Enter") {
            e.preventDefault();
            // Guarded on length rather than on the element: without
            // `noUncheckedIndexedAccess` the indexed read is typed `Entry`, so
            // an `entry !== undefined` check reads as dead code to the linter
            // while still being the thing that matters at runtime. The
            // highlight itself is kept in range — reset to 0 on input, and
            // wrapped modulo the list length by the arrow keys above.
            if (list.length === 0) return;
            choose(list[highlight()]);
        }
    }

    return (
        <dialog
            ref={(el) => (dialogEl = el)}
            class="command-palette"
            aria-label="Command palette"
            // A click that lands on the dialog itself landed on the backdrop:
            // every child is inside the panel below.
            onClick={(e) => {
                if (e.target === dialogEl) close();
            }}
            onClose={() => {
                setOpen(false);
                setQuery("");
                setDebounced("");
                setHighlight(0);
            }}
        >
            <div class="command-palette-panel">
                <div class="command-palette-search">
                    <Search size={16} aria-hidden="true" />
                    <input
                        ref={(el) => (inputEl = el)}
                        type="text"
                        role="combobox"
                        aria-label="Search commands"
                        aria-expanded="true"
                        aria-controls={listId}
                        aria-autocomplete="list"
                        aria-activedescendant={
                            rows().length > 0 ? `${listId}-${highlight()}` : undefined
                        }
                        placeholder="Go to…"
                        autocomplete="off"
                        value={query()}
                        onInput={(e) => {
                            setQuery(e.currentTarget.value);
                            setHighlight(0);
                        }}
                        onKeyDown={onKeyDown}
                    />
                </div>
                <ul
                    ref={(el) => (listEl = el)}
                    id={listId}
                    class="command-palette-list"
                    role="listbox"
                    aria-label="Commands"
                >
                    <Show when={nothingMatched()}>
                        <li class="command-palette-empty">
                            {/* "Nothing matched" is a claim, and it is false
                                while a request is still out. */}
                            {searching() ? "Searching…" : "No matching page"}
                        </li>
                    </Show>
                    <For each={groups()}>
                        {(group) => (
                            // role=presentation makes the nested group an
                            // effective child of the listbox, which is what the
                            // listbox > group > option contract asks for.
                            <li role="presentation">
                                <div class="command-palette-group">{group.name}</div>
                                <ul role="group" aria-label={group.name}>
                                    <For each={group.items}>
                                        {(item) => (
                                            <li
                                                id={`${listId}-${item.index}`}
                                                role="option"
                                                aria-selected={item.index === highlight()}
                                                class={
                                                    item.index === highlight()
                                                        ? "command-palette-option is-active"
                                                        : "command-palette-option"
                                                }
                                                onMouseEnter={() => setHighlight(item.index)}
                                                // mousedown, not click: the input
                                                // loses focus first and the row is
                                                // gone by the time click fires.
                                                onMouseDown={(e) => {
                                                    e.preventDefault();
                                                    choose(item.row);
                                                }}
                                            >
                                                <span class="command-palette-label">
                                                    {item.row.label}
                                                </span>
                                                <Show when={item.row.sub}>
                                                    {(sub) => (
                                                        <span class="command-palette-path">
                                                            {sub()}
                                                        </span>
                                                    )}
                                                </Show>
                                            </li>
                                        )}
                                    </For>
                                </ul>
                            </li>
                        )}
                    </For>
                </ul>
                <div class="command-palette-hint">
                    <span><kbd>↑</kbd><kbd>↓</kbd> to move</span>
                    <span><kbd>↵</kbd> to open</span>
                    <span><kbd>esc</kbd> to close</span>
                    {/* Says more rows may still arrive. Without it, results
                        landing 300ms after the list settled read as a glitch.
                        Suppressed when nothing has matched yet, because the
                        empty line is already saying exactly this. */}
                    <Show when={searching() && !nothingMatched()}>
                        <span class="command-palette-searching">Searching…</span>
                    </Show>
                </div>
            </div>
        </dialog>
    );
}
