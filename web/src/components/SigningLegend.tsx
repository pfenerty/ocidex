import "./SigningLegend.css";
import { For } from "solid-js";
import { SigningBadge } from "~/components/ui";
import { signingStatuses } from "~/utils/trust";

// MEANINGS are the one-line captions shown beside each badge. They are
// deliberately terser than the badge tooltips in trust.ts — the legend is
// scanned, the tooltip is read.
const MEANINGS: Record<(typeof signingStatuses)[number], string> = {
    verified: "signature checked and valid",
    signed: "signed, but registry has no trust anchor",
    unsigned: "no signing material found",
    artifact_missing: "gone from the registry",
    verification_failed: "check ran and failed",
};

// SigningLegend explains the signing column. Signed vs Verified is otherwise
// unreadable to a user, since the difference is whether the registry has a
// trust anchor configured — nothing about the artifact itself.
//
// The badges are rendered through SigningBadge so the legend cannot drift from
// the table it documents.
export default function SigningLegend() {
    return (
        <div class="signing-legend">
            <span class="signing-legend-title">Signing</span>
            <For each={signingStatuses}>
                {(status) => (
                    <span class="signing-legend-item">
                        <SigningBadge status={status} />
                        <span class="signing-legend-meaning">{MEANINGS[status]}</span>
                    </span>
                )}
            </For>
        </div>
    );
}
