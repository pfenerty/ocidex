import { readFileSync } from "fs";
import { resolve } from "path";
import { defineConfig, mergeConfig } from "vite";
import base from "./vite.config";

/**
 * Dev server pointed at the local authenticated rig (`scripts/dev-auth.sh`),
 * signed in as a local admin.
 *
 * This is the counterpart to `vite.config.live.ts`. That one proxies to
 * production, which makes it signed-out and read-only, so `/dashboard`,
 * `/clusters` and `/admin` — a third of the app — could never be looked at in
 * a browser. Everything here is local instead: this branch's API, a throwaway
 * Postgres, fixture data. Writes are safe because nothing leaves the machine.
 *
 * Authentication is not a bypass. `internal/api/middleware.go` already treats
 * `Authorization: Bearer <api-key>` as equivalent to a session cookie, and
 * `hasWriteAccess` grants writes to a `read-write` key, so the proxy simply
 * presents the key the rig minted. No OAuth, no cookie forgery, and no
 * dev-only branch in the shipped binary.
 *
 * The key is generated per machine into `.dev/` (gitignored) and is not a
 * credential for anything that exists outside this laptop.
 */
const KEY_FILE = resolve(__dirname, "../.dev/dev-auth.env");

function devAPIKey(): string {
    let contents: string;
    try {
        contents = readFileSync(KEY_FILE, "utf8");
    } catch {
        throw new Error(
            `No local dev credentials at ${KEY_FILE}.\n` +
                `Start the rig first:  make dev-auth-up`,
        );
    }
    const match = /^OCIDEX_DEV_API_KEY=(.+)$/m.exec(contents);
    if (match?.[1] === undefined) {
        throw new Error(`${KEY_FILE} has no OCIDEX_DEV_API_KEY line — try: make dev-auth-reset`);
    }
    return match[1].trim();
}

const target = "http://127.0.0.1:8080";

export default mergeConfig(
    base,
    defineConfig({
        server: {
            // Distinct from :3000 (local API, signed out) and :3100 (prod,
            // signed out) so all three can run at once.
            port: 3200,
            proxy: {
                "/api": {
                    target,
                    changeOrigin: false,
                    configure: (proxy) => {
                        const key = devAPIKey();
                        proxy.on("proxyReq", (proxyReq) => {
                            // Only set what is absent: a request that already
                            // carries its own Authorization header (a test of
                            // the 401 path) should stay unauthenticated.
                            if (!proxyReq.getHeader("authorization")) {
                                proxyReq.setHeader("authorization", `Bearer ${key}`);
                            }
                        });
                    },
                },
                "/auth": { target, changeOrigin: false },
                "/health": { target, changeOrigin: false },
                "/ready": { target, changeOrigin: false },
            },
        },
    }),
);
