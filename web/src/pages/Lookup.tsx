import { For, Show, createEffect } from "solid-js";
import type { JSX } from "solid-js";
import { A, useNavigate, useSearchParams } from "@solidjs/router";
import {
    useArtifactLookup,
    useSBOMLookup,
    conflictCandidates,
    isNotFound,
    type LookupCandidate,
} from "~/api/queries/lookup";
import { EmptyState, ErrorBox, Loading } from "~/components/Feedback";
import NotFound from "~/pages/NotFound";
import { PageHeader } from "~/components/ui";

/** First value of a search param, since the router types them as string | string[]. */
function one(v: string | string[] | undefined): string | undefined {
    return Array.isArray(v) ? v[0] : v;
}

interface ResolverViewProps {
    /** Human-readable resource name, used in the disambiguation copy. */
    resource: string;
    /** Canonical route for a resolved id, e.g. (id) => `/artifacts/${id}`. */
    canonicalPath: (id: string) => string;
    /** True once the query string carries enough to attempt a lookup. */
    ready: boolean;
    /** What the caller must supply when `ready` is false. */
    requirement: string;
    query: {
        isLoading: boolean;
        isError: boolean;
        error: unknown;
        data: { id: string } | undefined;
    };
}

/**
 * Shared body of the ADR-042 R7 resolver routes. A resolver URL is a redirect,
 * not a page: on a unique match it replaces itself with the canonical UUID
 * route, so the back button returns to whatever linked here rather than
 * bouncing off the resolver again.
 */
function ResolverView(props: ResolverViewProps): JSX.Element {
    const navigate = useNavigate();

    createEffect(() => {
        const id = props.query.data?.id;
        if (id !== undefined && id !== "") {
            navigate(props.canonicalPath(id), { replace: true });
        }
    });

    const candidates = (): LookupCandidate[] | null =>
        props.query.isError ? conflictCandidates(props.query.error) : null;

    return (
        <Show when={props.ready} fallback={<EmptyState title="Incomplete lookup" message={props.requirement} />}>
            <Show when={!props.query.isLoading} fallback={<Loading message={`Resolving ${props.resource}…`} />}>
                <Show when={props.query.isError} fallback={<Loading message={`Resolving ${props.resource}…`} />}>
                    <Show when={!isNotFound(props.query.error)} fallback={<NotFound />}>
                        <Show
                            when={candidates()}
                            fallback={<ErrorBox error={props.query.error} />}
                        >
                            {(list) => (
                                <>
                                    <PageHeader
                                        title="Multiple matches"
                                        subtitle={
                                            <>
                                                {list().length} {props.resource}s match this
                                                link. Pick one, or add another qualifier to
                                                the URL to make it resolve on its own.
                                            </>
                                        }
                                    />
                                    <ul class="flex flex-col gap-2">
                                        <For each={list()}>
                                            {(candidate) => (
                                                <li class="card">
                                                    <A
                                                        href={props.canonicalPath(candidate.id)}
                                                        class="flex flex-wrap gap-2 items-center"
                                                    >
                                                        <CandidateQualifiers
                                                            qualifiers={candidate.qualifiers}
                                                            fallback={candidate.id}
                                                        />
                                                    </A>
                                                </li>
                                            )}
                                        </For>
                                    </ul>
                                </>
                            )}
                        </Show>
                    </Show>
                </Show>
            </Show>
        </Show>
    );
}

/** Renders the qualifier values that distinguish one candidate from the rest. */
function CandidateQualifiers(props: {
    qualifiers: Record<string, string>;
    fallback: string;
}): JSX.Element {
    const entries = () => Object.entries(props.qualifiers);
    return (
        <Show when={entries().length > 0} fallback={<span>{props.fallback}</span>}>
            <For each={entries()}>
                {([key, value]) => (
                    <span class="badge">
                        {key}: {value}
                    </span>
                )}
            </For>
        </Show>
    );
}

/** GET /artifacts/lookup?name=…&type=…&group= — ADR-042 R4 artifact ladder. */
export function ArtifactLookup(): JSX.Element {
    const [searchParams] = useSearchParams();
    const params = () => ({
        name: one(searchParams.name) ?? "",
        type: one(searchParams.type),
        group: one(searchParams.group),
    });
    const query = useArtifactLookup(params);

    return (
        <ResolverView
            resource="artifact"
            canonicalPath={(id) => `/artifacts/${id}`}
            ready={params().name !== ""}
            requirement="This link needs a name query parameter, e.g. /artifacts/lookup?name=ghcr.io/pfenerty/ocidex."
            query={query}
        />
    );
}

/** GET /sboms/lookup?artifact=…&version=…(&arch=&flavor=) or ?digest=… — ADR-042 R4. */
export function SBOMLookup(): JSX.Element {
    const [searchParams] = useSearchParams();
    const params = () => ({
        artifact: one(searchParams.artifact),
        version: one(searchParams.version),
        arch: one(searchParams.arch),
        flavor: one(searchParams.flavor),
        digest: one(searchParams.digest),
    });
    const query = useSBOMLookup(params);
    const ready = () => {
        const p = params();
        return (
            (p.digest ?? "") !== "" ||
            ((p.artifact ?? "") !== "" && (p.version ?? "") !== "")
        );
    };

    return (
        <ResolverView
            resource="SBOM"
            canonicalPath={(id) => `/sboms/${id}`}
            ready={ready()}
            requirement="This link needs either a digest, or both artifact and version query parameters."
            query={query}
        />
    );
}
