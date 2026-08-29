/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_API_URL?: string;

    /**
     * Comma-separated seeded persona usernames. Defined only by
     * vite.config.auth.ts, from the key names in .dev/dev-auth.env, and never
     * in a production build — its presence is what gates the dev persona
     * switcher (web/src/components/dev/PersonaSwitcher.tsx).
     */
    readonly VITE_DEV_PERSONAS?: string;

    /** Vite's own build-mode flag; false in a production bundle. */
    readonly DEV: boolean;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
