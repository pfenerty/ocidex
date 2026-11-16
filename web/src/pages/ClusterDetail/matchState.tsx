import { StatusChip } from "~/components/ui";
import type { WorkloadMatchState } from "~/api/client";
import { MATCH_STATUS } from "~/utils/status";

/**
 * A workload's match state as a chip. The words, tone and meaning live in
 * MATCH_STATUS (~/utils/status), which CoverageBand's legend also reads, so the
 * legend and the rows cannot disagree about what colour a gap is
 * (ocidex-iz0r.4). Hue alone cannot carry "a gap, not a pass", so every state
 * says in words which gap it is.
 */
export function MatchStatePill(props: { state: WorkloadMatchState }) {
    return <StatusChip status={MATCH_STATUS[props.state]} />;
}
