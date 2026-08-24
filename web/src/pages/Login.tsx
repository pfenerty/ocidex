import { API_BASE_URL } from "~/api/client";
import { GitHubMark } from "~/components/icons/GitHubMark";

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
                        <GitHubMark />
                        Continue with GitHub
                    </a>
                </div>
            </div>
        </div>
    );
}
