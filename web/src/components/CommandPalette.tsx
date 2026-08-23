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
 * This is the shell: the entries are the static route list above and filtering
 * is synchronous, for the reason `Combobox` already documents — the candidates
 * are in memory, so a debounce would only add lag between a keystroke and the
 * list narrowing. Live search (ocidex-ag4q.46) adds a debounced fan-out
 * *beside* these entries; it does not replace them.
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

    const matches = createMemo(() => {
        const terms = query().toLowerCase().split(/\s+/).filter((t) => t !== "");
        if (terms.length === 0) return available();
        return available().filter((e) => {
            const hay = `${e.label} ${e.group} ${e.path} ${e.keywords ?? ""}`.toLowerCase();
            return terms.every((t) => hay.includes(t));
        });
    });

    // Groups are derived from the filtered list rather than filtered per group,
    // so a group that matches nothing disappears instead of leaving a heading
    // over empty space. The flat index rides along because the highlight is
    // flat — arrow keys cross group boundaries without the user noticing them.
    const groups = createMemo(() => {
        const out: { name: string; items: { entry: Entry; index: number }[] }[] = [];
        matches().forEach((entry, index) => {
            let g = out.find((o) => o.name === entry.group);
            if (g === undefined) {
                g = { name: entry.group, items: [] };
                out.push(g);
            }
            g.items.push({ entry, index });
        });
        return out;
    });

    function close(): void {
        setOpen(false);
        dialogEl?.close();
        setQuery("");
        setHighlight(0);
    }

    function choose(entry: Entry): void {
        close();
        navigate(entry.path);
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
        const list = matches();
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
                            matches().length > 0 ? `${listId}-${highlight()}` : undefined
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
                    <Show when={matches().length === 0}>
                        <li class="command-palette-empty">No matching page</li>
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
                                        {(row) => (
                                            <li
                                                id={`${listId}-${row.index}`}
                                                role="option"
                                                aria-selected={row.index === highlight()}
                                                class={
                                                    row.index === highlight()
                                                        ? "command-palette-option is-active"
                                                        : "command-palette-option"
                                                }
                                                onMouseEnter={() => setHighlight(row.index)}
                                                // mousedown, not click: the input
                                                // loses focus first and the row is
                                                // gone by the time click fires.
                                                onMouseDown={(e) => {
                                                    e.preventDefault();
                                                    choose(row.entry);
                                                }}
                                            >
                                                <span class="command-palette-label">
                                                    {row.entry.label}
                                                </span>
                                                <span class="command-palette-path">
                                                    {row.entry.path}
                                                </span>
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
                </div>
            </div>
        </dialog>
    );
}
