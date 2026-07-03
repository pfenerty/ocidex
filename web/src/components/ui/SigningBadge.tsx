import { Match, Switch } from "solid-js";
import { Shield, ShieldAlert, ShieldCheck, ShieldX } from "lucide-solid";
import { Badge } from "./Badge";

const iconStyle = { "vertical-align": "middle", "margin-right": "3px" };

export function SigningBadge(props: { status: string }) {
    return (
        <Switch fallback={<Badge><Shield size={12} style={iconStyle} />Unsigned</Badge>}>
            <Match when={props.status === "verified"}>
                <Badge variant="success"><ShieldCheck size={12} style={iconStyle} />Verified</Badge>
            </Match>
            <Match when={props.status === "verification_failed"}>
                <Badge variant="danger"><ShieldX size={12} style={iconStyle} />Verification failed</Badge>
            </Match>
            <Match when={props.status === "signed"}>
                <Badge variant="warning"><ShieldAlert size={12} style={iconStyle} />Signed</Badge>
            </Match>
        </Switch>
    );
}
