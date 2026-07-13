import { relativeDate, formatDateTime } from "~/utils/format";

export function TimestampCell(props: { iso: string }) {
    return <span title={formatDateTime(props.iso)}>{relativeDate(props.iso)}</span>;
}
