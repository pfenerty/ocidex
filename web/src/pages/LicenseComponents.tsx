import { createSignal, Show, For } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useLicenses, useLicenseComponents } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import PurlLink from "~/components/PurlLink";

export default function LicenseComponents() {
    const params = useParams<{ id: string }>();
    const [offset, setOffset] = createSignal(0);
    const limit = 50;

    const licenseQuery = useLicenses(() => ({ limit: 200 }));

    const licenseName = () => {
        const match = licenseQuery.data?.data.find((l) => l.id === params.id);
        return match?.name ?? params.id;
    };

    const licenseSpdx = () => {
        const match = licenseQuery.data?.data.find((l) => l.id === params.id);
        return match?.spdxId;
    };

    const query = useLicenseComponents(
        () => params.id,
        () => ({ limit, offset: offset() }),
    );

    return (
        <>
            <div class="breadcrumb">
                <A href="/licenses">Licenses</A>
                <span class="separator">/</span>
                <span>{licenseName()}</span>
                <span class="separator">/</span>
                <span>Components</span>
            </div>

            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>{licenseName()}</h2>
                        <p>
                            <Show when={licenseSpdx()}>
                                <span class="badge badge-primary">
                                    {licenseSpdx()}
                                </span>{" "}
                            </Show>
                            Components using this license
                        </p>
                    </div>
                </div>
            </div>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    <Show
                        when={query.data && query.data.data.length > 0}
                        fallback={
                            <EmptyState
                                title="No components"
                                message="No components are associated with this license."
                            />
                        }
                    >
                        <div class="card">
                            <div class="table-wrapper">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Component</th>
                                            <th>Type</th>
                                            <th>Version</th>
                                            <th>Package</th>
                                            <th>Found In</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <For each={query.data!.data}>
                                            {(component) => (
                                                <tr>
                                                    <td>
                                                        <A
                                                            href={`/components/${component.id}`}
                                                        >
                                                            {component.group
                                                                ? `${component.group}/`
                                                                : ""}
                                                            {component.name}
                                                        </A>
                                                    </td>
                                                    <td>
                                                        <span class="badge">
                                                            {component.type}
                                                        </span>
                                                    </td>
                                                    <td class="mono">
                                                        {component.version ??
                                                            "—"}
                                                    </td>
                                                    <td class="truncate">
                                                        <Show
                                                            when={
                                                                component.purl
                                                            }
                                                            fallback={
                                                                <span class="text-muted">
                                                                    —
                                                                </span>
                                                            }
                                                        >
                                                            <PurlLink
                                                                purl={
                                                                    component.purl!
                                                                }
                                                                showBadge
                                                            />
                                                        </Show>
                                                    </td>
                                                    <td>
                                                        <A
                                                            href={`/sboms/${component.sbomId}`}
                                                            class="text-sm"
                                                        >
                                                            View SBOM →
                                                        </A>
                                                    </td>
                                                </tr>
                                            )}
                                        </For>
                                    </tbody>
                                </table>
                            </div>
                            <Pagination
                                pagination={query.data!.pagination}
                                onPageChange={setOffset}
                            />
                        </div>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
