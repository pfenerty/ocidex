import { Boxes, Container, Package } from "lucide-solid";
import type { JSX } from "solid-js";
import { Badge } from "./Badge";

const iconStyle = { "vertical-align": "middle", "margin-right": "3px" };

function typeIcon(type: string): JSX.Element {
    switch (type.toLowerCase()) {
        case "container": return <Container size={12} style={iconStyle} />;
        case "library":   return <Package size={12} style={iconStyle} />;
        default:          return <Boxes size={12} style={iconStyle} />;
    }
}

export function TypeBadge(props: { type: string }) {
    return <Badge>{typeIcon(props.type)}{props.type}</Badge>;
}
