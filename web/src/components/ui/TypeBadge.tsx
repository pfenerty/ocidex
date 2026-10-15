import { Boxes, Container, Package } from "lucide-solid";
import type { JSX } from "solid-js";
import { Badge } from "./Badge";

const iconClass = "mr-[3px] align-middle";

function typeIcon(type: string): JSX.Element {
    switch (type.toLowerCase()) {
        case "container": return <Container size={12} class={iconClass} />;
        case "library":   return <Package size={12} class={iconClass} />;
        default:          return <Boxes size={12} class={iconClass} />;
    }
}

export function TypeBadge(props: { type: string }) {
    return <Badge>{typeIcon(props.type)}{props.type}</Badge>;
}
