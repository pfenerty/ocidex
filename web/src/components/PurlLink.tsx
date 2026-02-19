import { Show } from "solid-js";
import { purlToRegistryUrl, purlTypeLabel, purlDisplayName } from "~/utils/purl";

/** Renders a PURL as an external link to the appropriate package registry. */
export default function PurlLink(props: { purl: string; showBadge?: boolean }) {
  const url = () => purlToRegistryUrl(props.purl);
  const label = () => purlTypeLabel(props.purl);

  return (
    <span class="purl-link">
      <Show when={props.showBadge && label()}>
        <span class="badge badge-sm">{label()}</span>{" "}
      </Show>
      <Show
        when={url()}
        fallback={<span class="mono text-sm" title={props.purl}>{purlDisplayName(props.purl)}</span>}
      >
        <a
          href={url()!}
          target="_blank"
          rel="noopener noreferrer"
          class="mono text-sm"
          title={props.purl}
        >
          {purlDisplayName(props.purl)}
          <svg class="external-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
            <polyline points="15 3 21 3 21 9" />
            <line x1="10" y1="14" x2="21" y2="3" />
          </svg>
        </a>
      </Show>
    </span>
  );
}
