import { Show } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";

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

interface Annotation {
    key: string;
    value: string;
}

const columns: Column<Annotation>[] = [
    {
        header: "Key",
        render: (a) => <span class="font-mono text-sm">{a.key}</span>,
    },
    {
        header: "Value",
        // Annotation values are unbounded free text (a full commit message, a
        // whole licence list), and without this a single one stretches the
        // column past the viewport.
        render: (a) => <span class="font-mono text-sm break-all">{a.value}</span>,
    },
];

/** Collapsible key/value annotations table, filtering out already-displayed keys. */
export function AnnotationsSection(props: {
    title: string;
    annotations: Record<string, string>;
}) {
    const entries = (): Annotation[] =>
        Object.entries(props.annotations)
            .filter(([k]) => !OCI_SKIP_KEYS.has(k))
            .map(([key, value]) => ({ key, value }));

    return (
        <Show when={entries().length > 0}>
            <details class="mt-4">
                <summary class="text-muted text-sm cursor-pointer">
                    {props.title} ({entries().length})
                </summary>
                <DataTable
                    /* Already inside ImageMetadataCard's card — a second one
                       here is two borders and two lots of padding. */
                    bare
                    class="mt-2"
                    columns={columns}
                    rows={entries()}
                    loading={false}
                    isError={false}
                    emptyTitle="No annotations"
                />
            </details>
        </Show>
    );
}
