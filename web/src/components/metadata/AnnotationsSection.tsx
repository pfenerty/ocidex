import { Show, For } from "solid-js";

export const OCI_SKIP_KEYS = new Set([
    "org.opencontainers.image.version",
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.authors",
    "org.opencontainers.image.description",
    "org.opencontainers.image.base.name",
    "org.opencontainers.image.url",
    "org.opencontainers.image.documentation",
    "org.opencontainers.image.vendor",
    "org.opencontainers.image.licenses",
    "org.opencontainers.image.title",
    "org.opencontainers.image.base.digest",
    "org.opencontainers.image.created",
]);

/** Collapsible key/value annotations table, filtering out already-displayed keys. */
export function AnnotationsSection(props: {
    title: string;
    annotations: Record<string, string>;
}) {
    const entries = () =>
        Object.entries(props.annotations).filter(
            ([k]) => !OCI_SKIP_KEYS.has(k),
        );

    return (
        <Show when={entries().length > 0}>
            <details class="mt-md">
                <summary
                    class="text-muted text-sm"
                    style={{ cursor: "pointer" }}
                >
                    {props.title} ({entries().length})
                </summary>
                <div class="table-wrapper mt-sm">
                    <table>
                        <thead>
                            <tr>
                                <th>Key</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={entries()}>
                                {([key, value]) => (
                                    <tr>
                                        <td class="mono text-sm">{key}</td>
                                        <td
                                            class="mono text-sm"
                                            style={{
                                                "word-break": "break-all",
                                            }}
                                        >
                                            {value}
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </details>
        </Show>
    );
}
