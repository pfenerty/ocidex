import { API_BASE_URL } from "~/api/client";

export default function Login() {
    return (
        <div class="flex flex-1 items-center justify-center bg-[var(--color-bg)]">
            <div class="flex flex-col items-center gap-8 p-12 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl w-full max-w-[360px]">
                {/* Logo */}
                <div class="text-center">
                    <h1 class="text-3xl font-bold tracking-tight text-[var(--color-text)] leading-none mb-1.5">
                        OCI<span class="text-[var(--color-primary)]">Dex</span>
                    </h1>
                    <p class="text-[0.8125rem] text-[var(--color-text-muted)] tracking-widest uppercase">
                        SBOM Explorer
                    </p>
                </div>

                {/* Divider */}
                <div class="w-full h-px bg-[var(--color-border)]" />

                {/* Sign-in */}
                <div class="text-center w-full">
                    <p class="text-[0.8125rem] text-[var(--color-text-muted)] mb-5">
                        Sign in to access the dashboard
                    </p>
                    <a
                        href={`${API_BASE_URL}/auth/login`}
                        target="_self"
                        class="inline-flex items-center gap-2.5 px-5 py-2.5 bg-[var(--color-elevated)] border border-[var(--color-border)] rounded-md text-[var(--color-text)] text-sm font-medium no-underline transition-[background,border-color] duration-150 w-full justify-center hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-hover)]"
                    >
                        <svg height="16" width="16" viewBox="0 0 16 16" fill="currentColor">
                            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                        </svg>
                        Continue with GitHub
                    </a>
                </div>
            </div>
        </div>
    );
}
