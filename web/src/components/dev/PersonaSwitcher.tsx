import "./PersonaSwitcher.css";
import { createSignal, For, Show } from "solid-js";
import { UserCog } from "lucide-solid";
import { API_BASE_URL } from "~/api/client";
import { useAuth } from "~/context/auth";

/**
 * The dev rig's persona switcher.
 *
 * Why it exists: every authorization change in this project has been verified
 * by unit test alone, because the rig could only ever be one principal. A
 * viewer's `/admin`, a non-owner's private namespace and an outsider's
 * cross-tenant 404 are all things a person has to *look at* to trust, and
 * looking at them meant restarting the rig with a different key.
 *
 * Why it mints a session instead of swapping a Bearer key: the API-key path
 * skips CreateSession/ValidateSession entirely, so a rig driven by keys proves
 * nothing about the cookie path production browsers actually take. This posts
 * to the dev-only mint endpoint (internal/api/devauth.go) and reloads, so from
 * the first click onward the browser is authenticated exactly as production
 * authenticates it.
 *
 * It is doubly gated: `import.meta.env.DEV` removes it from any production
 * build, and VITE_DEV_PERSONAS is defined only by vite.config.auth.ts, so it
 * stays absent from the plain :3000 dev server and from the prod-proxied :3100
 * rig — neither has a local API with the mint endpoint registered.
 */

/**
 * The seeded personas, injected at config time by vite.config.auth.ts, which
 * derives them from the key names in .dev/dev-auth.env. Deriving rather than
 * hardcoding means scripts/dev-auth.sh's PERSONAS array stays the single
 * source of truth: add a persona there and it appears here on the next rig
 * start, with no second list to forget.
 */
export function personaRoster(): string[] {
    const raw = import.meta.env.VITE_DEV_PERSONAS;
    if (raw === undefined || raw === "") return [];
    return raw.split(",").map((p) => p.trim()).filter(Boolean);
}

export default function PersonaSwitcher() {
    const { user } = useAuth();
    const personas = personaRoster();
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal<string | undefined>();

    async function become(username: string) {
        if (!username) return;
        setBusy(true);
        setError(undefined);
        try {
            const res = await fetch(`${API_BASE_URL}/api/v1/dev/session`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify({ username }),
            });
            if (!res.ok) {
                // A 404 here means the API is not running with
                // ENVIRONMENT=development, which is the one failure worth
                // naming: everything else about the rig would still look fine.
                setError(res.status === 404 ? "mint endpoint not registered" : `HTTP ${res.status}`);
                setBusy(false);
                return;
            }
            // A full reload rather than refetch(): every page's queries, the
            // visibility-filtered lists most of all, were fetched as the
            // previous persona. Re-authenticating without re-fetching them
            // would show one persona's identity over another's data, which is
            // precisely the confusion this control exists to prevent.
            window.location.reload();
        } catch {
            setError("API unreachable");
            setBusy(false);
        }
    }

    async function signOut() {
        setBusy(true);
        await fetch(`${API_BASE_URL}/auth/logout`, { method: "POST", credentials: "include" });
        window.location.reload();
    }

    return (
        <Show when={personas.length > 0}>
            <div class="persona-switcher" data-testid="persona-switcher">
                <UserCog size={14} aria-hidden="true" />
                <label class="persona-switcher-label" for="persona-select">
                    Persona
                </label>
                <select
                    id="persona-select"
                    class="persona-switcher-select"
                    disabled={busy()}
                    value={user()?.display_name ?? ""}
                    onChange={(e) => void become(e.currentTarget.value)}
                >
                    <option value="">signed out</option>
                    <For each={personas}>{(p) => <option value={p}>{p}</option>}</For>
                </select>
                <Show when={user()}>
                    <button
                        type="button"
                        class="persona-switcher-signout"
                        disabled={busy()}
                        onClick={() => void signOut()}
                    >
                        sign out
                    </button>
                </Show>
                <Show when={error()}>
                    {(msg) => <span class="persona-switcher-error">{msg()}</span>}
                </Show>
            </div>
        </Show>
    );
}
