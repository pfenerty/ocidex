import { readFileSync } from "fs";
import { resolve } from "path";
import { defineConfig, mergeConfig } from "vite";
import base from "./vite.config";

/**
 * Dev server pointed at the local authenticated rig (`scripts/dev-auth.sh`).
 *
 * This is the counterpart to `vite.config.live.ts`. That one proxies to
 * production, which makes it signed-out and read-only, so `/dashboard`,
 * `/clusters` and `/admin` — a third of the app — could never be looked at in
 * a browser. Everything here is local instead: this branch's API, a throwaway
 * Postgres, fixture data. Writes are safe because nothing leaves the machine.
 *
 * Authentication is a real session, not a bypass and not an injected key.
 * The proxy used to attach the rig's admin API key to every request, which
 * made the rig permanently one principal *and* routed it down a code path
 * (`Authorization: Bearer`) that production browsers never take — so the
 * cookie half of the auth system had no browser coverage at all. Now the page
 * starts signed out and the persona switcher
 * (`web/src/components/dev/PersonaSwitcher.tsx`) mints a genuine session
 * cookie through the dev-only endpoint in `internal/api/devauth.go`.
 *
 * The roster below is derived from the key names the rig wrote, so
 * `scripts/dev-auth.sh`'s PERSONAS array stays the only place personas are
 * declared.
 */
const KEY_FILE = resolve(__dirname, "../.dev/dev-auth.env");

function devPersonas(): string[] {
    let contents: string;
    try {
        contents = readFileSync(KEY_FILE, "utf8");
    } catch {
        throw new Error(
            `No local dev credentials at ${KEY_FILE}.\n` +
                `Start the rig first:  make dev-auth-up`,
        );
    }
    const names = [...contents.matchAll(/^OCIDEX_DEV_KEY_(.+)_RW=/gm)].map((m) =>
        m[1].toLowerCase(),
    );
    if (names.length === 0) {
        throw new Error(
            `${KEY_FILE} declares no personas (no OCIDEX_DEV_KEY_*_RW lines) — try: make dev-auth-reset`,
        );
    }
    return names;
}

const target = "http://127.0.0.1:8080";

export default mergeConfig(
    base,
    defineConfig({
        // Read at config time, so a persona added to scripts/dev-auth.sh shows
        // up on the next `make frontend-dev-auth` with nothing else to change.
        define: {
            "import.meta.env.VITE_DEV_PERSONAS": JSON.stringify(devPersonas().join(",")),
        },
        server: {
            // Distinct from :3000 (local API, signed out) and :3100 (prod,
            // signed out) so all three can run at once.
            port: 3200,
            proxy: {
                // changeOrigin:false so the API sees the browser's Host and
                // the session cookie stays same-origin from :3200.
                "/api": { target, changeOrigin: false },
                "/auth": { target, changeOrigin: false },
                "/health": { target, changeOrigin: false },
                "/ready": { target, changeOrigin: false },
            },
        },
    }),
);
