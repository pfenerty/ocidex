import { Show } from "solid-js";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";

export function SpdxBadgeCell(props: { spdxId?: string }) {
    return (
        <Show
            when={props.spdxId !== undefined}
            fallback={<span class="text-muted">—</span>}
        >
            <span class="badge badge-primary">{props.spdxId}</span>
        </Show>
    );
}

export function LicenseCategoryCell(props: { category?: string }) {
    return (
        <Show
            when={props.category}
            fallback={<span class="text-muted">—</span>}
        >
            {(category) => (
                <span class={`badge ${CATEGORY_COLORS[category()]?.badge ?? ""}`}>
                    {category()}
                </span>
            )}
        </Show>
    );
}
