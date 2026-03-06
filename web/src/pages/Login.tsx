import { API_BASE_URL } from "~/api/client";

export default function Login() {
    return (
        <div style={{
            display: "flex",
            flex: "1",
            "align-items": "center",
            "justify-content": "center",
            background: "var(--color-bg)",
        }}>
            <div style={{
                display: "flex",
                "flex-direction": "column",
                "align-items": "center",
                gap: "2rem",
                padding: "3rem",
                background: "var(--color-surface)",
                border: "1px solid var(--color-border)",
                "border-radius": "0.75rem",
                width: "100%",
                "max-width": "360px",
            }}>
                {/* Logo */}
                <div style={{ "text-align": "center" }}>
                    <h1 style={{
                        "font-size": "2rem",
                        "font-weight": "700",
                        "letter-spacing": "-0.03em",
                        color: "var(--color-text)",
                        "line-height": "1",
                        "margin-bottom": "0.375rem",
                    }}>
                        OCI<span style={{ color: "var(--color-primary)" }}>Dex</span>
                    </h1>
                    <p style={{
                        "font-size": "0.8125rem",
                        color: "var(--color-text-muted)",
                        "letter-spacing": "0.06em",
                        "text-transform": "uppercase",
                    }}>
                        SBOM Explorer
                    </p>
                </div>

                {/* Divider */}
                <div style={{
                    width: "100%",
                    height: "1px",
                    background: "var(--color-border)",
                }} />

                {/* Sign-in */}
                <div style={{ "text-align": "center", width: "100%" }}>
                    <p style={{
                        "font-size": "0.8125rem",
                        color: "var(--color-text-muted)",
                        "margin-bottom": "1.25rem",
                    }}>
                        Sign in to access the dashboard
                    </p>
                    <a
                        href={`${API_BASE_URL}/auth/login`}
                        target="_self"
                        style={{
                            display: "inline-flex",
                            "align-items": "center",
                            gap: "0.625rem",
                            padding: "0.625rem 1.25rem",
                            background: "var(--color-elevated)",
                            border: "1px solid var(--color-border)",
                            "border-radius": "0.375rem",
                            color: "var(--color-text)",
                            "font-size": "0.875rem",
                            "font-weight": "500",
                            "text-decoration": "none",
                            transition: "background 0.15s, border-color 0.15s",
                            width: "100%",
                            "justify-content": "center",
                        }}
                        onMouseEnter={(e) => {
                            e.currentTarget.style.background = "var(--color-surface-hover)";
                            e.currentTarget.style.borderColor = "var(--color-border-hover)";
                        }}
                        onMouseLeave={(e) => {
                            e.currentTarget.style.background = "var(--color-elevated)";
                            e.currentTarget.style.borderColor = "var(--color-border)";
                        }}
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
