import { useToast } from "~/context/toast";
import { copyText } from "~/utils/clipboard";
import { shortDigest } from "~/utils/format";

interface CopyDigestProps {
    digest: string;
    artifactName?: string;
    full?: boolean;
    class?: string;
}

export default function CopyDigest(props: CopyDigestProps) {
    const toast = useToast();

    const ref = () =>
        props.artifactName !== undefined
            ? `${props.artifactName}@${props.digest}`
            : props.digest;

    const copy = async () => {
        try {
            await copyText(ref());
            toast("Copied to clipboard", "success");
        } catch {
            toast("Failed to copy", "error");
        }
    };

    const classes = () =>
        props.class !== undefined
            ? `copy-btn mono text-sm ${props.class}`
            : "copy-btn mono text-sm";

    return (
        <button
            type="button"
            class={classes()}
            title={`Click to copy: ${ref()}`}
            onClick={() => void copy()}
        >
            {props.full === true ? props.digest : shortDigest(props.digest)}
        </button>
    );
}
