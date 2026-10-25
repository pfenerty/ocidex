import { Show } from "solid-js";
import { Card, CardHeader, DetailField, DetailGrid, PageHeader } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { DATA_SOURCES, type DataSource } from "./dataSources";
import { useServerVersion } from "~/api/queries";
import { formatDateTime } from "~/utils/format";

/**
 * The bundle's license texts. A static file served beside the bundle, not a
 * route, so it is a plain link held in a constant: a literal href would read
 * as a link to an undeclared route.
 */
const THIRD_PARTY_LICENSES = "/third-party-licenses.txt";

const SOURCE_COLUMNS: Column<DataSource>[] = [
    {
        header: "Source",
        render: (src) => (
            <Show when={src.url} fallback={src.name}>
                {(url) => (
                    <a href={url()} target="_blank" rel="noopener">
                        {src.name}
                    </a>
                )}
            </Show>
        ),
    },
    { header: "Used for", render: (src) => src.usedFor },
    { header: "Terms", render: (src) => src.terms },
];

/**
 * About is where OCIDex credits what it is built from and what it shows
 * (ocidex-7hhp): the open-source packages in the web bundle and server images,
 * and the vulnerability feeds whose advisories appear throughout the UI. Those
 * feeds' licenses (CC-BY, CC-BY-SA, the NVD notice) ask for attribution where
 * the data is displayed, which a file in the repository does not give.
 */
export default function About() {
    const server = useServerVersion();
    // "unknown" is the version package's sentinel for a build without that
    // field; it is shown as a dash rather than as if it were a value.
    const known = (v: string | undefined) => (v !== undefined && v !== "" && v !== "unknown" ? v : undefined);

    return (
        <>
            <PageHeader title="About OCIDex" subtitle="Open-source software and data this installation uses" />

            {/* What is running, for support and bug reports (ocidex-nps9.17). */}
            <Card class="mb-4">
                <CardHeader title="This installation" />
                <Show
                    when={server.data}
                    fallback={
                        <p class="text-muted">
                            {server.isError ? "Version information is unavailable." : "Loading…"}
                        </p>
                    }
                >
                    {(v) => (
                        <DetailGrid>
                            <DetailField label="Version" valueClass="font-mono">
                                {v().build}
                            </DetailField>
                            <DetailField label="Commit" valueClass="font-mono">
                                <Show when={known(v().commit)} fallback="—">
                                    {(c) => (
                                        <a href={`https://github.com/pfenerty/ocidex/commit/${c()}`} target="_blank" rel="noopener">
                                            {c().slice(0, 12)}
                                        </a>
                                    )}
                                </Show>
                            </DetailField>
                            <DetailField label="Built">
                                <Show when={known(v().builtAt)} fallback="—">
                                    {(d) => formatDateTime(d())}
                                </Show>
                            </DetailField>
                            <DetailField label="Vulnerability database">
                                <Show when={v().vulnDbBuiltAt} fallback="not yet matched">
                                    {(d) => `built ${formatDateTime(d())}`}
                                </Show>
                            </DetailField>
                        </DetailGrid>
                    )}
                </Show>
            </Card>

            <Card class="mb-4">
                <CardHeader title="Open-source licenses" />
                <p>
                    The web interface bundles third-party packages; their license texts are in{" "}
                    <a href={THIRD_PARTY_LICENSES} target="_blank" rel="noopener">
                        third-party-licenses.txt
                    </a>
                    .
                </p>
                <p class="text-muted">
                    Every OCIDex container image also carries the license texts of the software built
                    into it, under <span class="font-mono">/licenses</span>.
                </p>
            </Card>

            <DataTable
                columns={SOURCE_COLUMNS}
                rows={[...DATA_SOURCES]}
                loading={false}
                isError={false}
                emptyTitle="No data sources"
                caption={
                    <>
                        <CardHeader title="Vulnerability data sources" />
                        <p>
                            Vulnerability matches come from the{" "}
                            <a href="https://github.com/anchore/grype" target="_blank" rel="noopener">
                                grype
                            </a>{" "}
                            database, which Anchore builds daily from the public feeds below, each under
                            its own terms. Advisory text is shown as published, without modification.
                            Text from a share-alike source (Ubuntu) stays under that source's license.
                        </p>
                    </>
                }
            />
        </>
    );
}
