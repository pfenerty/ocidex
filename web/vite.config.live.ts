import base from "./vite.config";
import { defineConfig, mergeConfig } from "vite";

/**
 * Dev server with the API proxied to production instead of localhost:8080.
 *
 * `make frontend-dev` assumes a local API on :8080 backed by a local Postgres.
 * Neither runs in this environment (docker is unavailable), so every request
 * fails and a CSS or markup change cannot be looked at against real content.
 * This config keeps the local frontend — HMR and all — and points only the
 * data at prod.
 *
 * Two limits are inherent, not bugs to fix:
 *
 *   1. Signed out. The prod session cookie is scoped to ocidex.app and does not
 *      travel to localhost, so /dashboard, /clusters and /admin redirect to
 *      login. Authenticated surfaces stay unit-test-verified.
 *   2. Read only. These requests reach PRODUCTION. Anonymous callers only have
 *      read scope, so this is safe by construction — but never point this at a
 *      flow that writes, and never add credentials to it.
 *
 * A backend change is invisible here by definition: prod runs the deployed API,
 * not the branch. Frontend-only.
 */
const target = "https://ocidex.app";

export default mergeConfig(
    base,
    defineConfig({
        server: {
            // Deliberately not 3000: `make frontend-dev` should stay runnable
            // alongside this one, pointed at a real local API.
            port: 3100,
            proxy: {
                "/api": { target, changeOrigin: true, secure: true },
                "/auth": { target, changeOrigin: true, secure: true },
            },
        },
    }),
);
