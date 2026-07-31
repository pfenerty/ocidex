import { Show } from "solid-js";
import { Dynamic } from "solid-js/web";
import { Shield } from "lucide-solid";
import { Badge } from "./Badge";
import { trustStatus, trustBadgeVariant } from "~/utils/trust";

const iconStyle = { "vertical-align": "middle", "margin-right": "3px" };

// SigningBadge renders a signing status as a badge with an explanatory
// tooltip. Presentation is derived entirely from trust.ts so this component
// cannot drift from the other consumers of that table — it previously kept its
// own copy, which is how `artifact_missing` came to render as "Unsigned".
//
// An unrecognized status renders as its raw value rather than being relabelled,
// so a new server-side status is visibly unhandled instead of silently
// misreported.
export function SigningBadge(props: { status: string }) {
    const trust = () => trustStatus(props.status);

    return (
        <Show
            when={trust()}
            fallback={<Badge><Shield size={12} style={iconStyle} />{props.status}</Badge>}
        >
            {(t) => (
                <Badge variant={trustBadgeVariant(t().variant)} title={t().description}>
                    <Dynamic component={t().icon} size={12} style={iconStyle} />
                    {t().label}
                </Badge>
            )}
        </Show>
    );
}
