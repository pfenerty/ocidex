import { Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useApproval, useDecideApproval } from "~/api/queries";
import { useToast } from "~/context/toast";
import { Breadcrumb, Button, Card, PageHeader, QueryBoundary } from "~/components/ui";
import { TimestampCell } from "~/components/cells";
import { EmptyState } from "~/components/Feedback";
import { SkeletonText } from "~/components/Skeleton";
import "./Approval.css";

/**
 * One agent write held for approval (ADR-0058 A4). What you approve is the
 * effect OCIDex wrote from the stored request, and that stored request is what
 * runs. The agent's own note is shown apart, quoted and marked unverified: it is
 * the one thing on this page the agent wrote, and it can say anything.
 */
export default function Approval() {
    const params = useParams<{ id: string }>();
    const toast = useToast();
    const query = useApproval(() => params.id);
    const decide = useDecideApproval();

    const act = (approve: boolean) =>
        decide.mutate(
            { id: params.id, approve },
            {
                onSuccess: (a) => {
                    void query.refetch();
                    toast(approve ? (a.status === "executed" ? "Approved and run" : `Approved; it ran and returned ${a.resultStatus}`) : "Denied", approve && a.status !== "executed" ? "error" : "success");
                },
                onError: () => toast("Could not record the decision; it may no longer be pending", "error"),
            },
        );

    return (
        <>
            <PageHeader
                breadcrumb={<Breadcrumb items={[{ label: "Agents", href: "/admin/agents" }, { label: "Approval" }]} />}
                title="Agent request"
            />
            <QueryBoundary query={query} loading={<SkeletonText lines={6} />} empty={<EmptyState title="No such request" message="It may belong to someone else's agent." />}>
                {(a) => (
                    <Card class="approval">
                        <p class="approval-status" data-status={a().status}>
                            {a().status}
                        </p>
                        <h2 class="approval-effect">{a().effect}</h2>
                        <dl class="approval-facts">
                            <div><dt>Asked by</dt><dd>{a().agentLabel ?? "an agent key"}</dd></div>
                            <div><dt>Asked</dt><dd><TimestampCell iso={a().createdAt} /></dd></div>
                            <Show when={a().status === "pending"}>
                                <div><dt>Expires</dt><dd><TimestampCell iso={a().expiresAt} /></dd></div>
                            </Show>
                            <div><dt>Needs</dt><dd class="font-mono">{a().capability}</dd></div>
                        </dl>
                        <details class="approval-request">
                            <summary>{a().status === "pending" ? "Exact request that will run" : "Exact request"}</summary>
                            <pre class="font-mono text-sm">{`${a().method} ${a().path}${a().body !== undefined && a().body !== "" ? `\n\n${a().body}` : ""}`}</pre>
                        </details>
                        <Show when={a().reason}>
                            {(r) => (
                                <blockquote class="approval-reason">
                                    <span class="approval-reason-label">Note from the agent (not verified; it is not a description of what will run)</span>
                                    {r()}
                                </blockquote>
                            )}
                        </Show>
                        <Show when={a().status === "pending" && a().canDecide}>
                            <div class="flex gap-2">
                                <Button variant="primary" disabled={decide.isPending} onClick={() => act(true)}>
                                    Approve and run
                                </Button>
                                <Button disabled={decide.isPending} onClick={() => act(false)}>
                                    Deny
                                </Button>
                            </div>
                        </Show>
                        <Show when={a().status === "pending" && !a().canDecide}>
                            <p class="text-muted mb-0">
                                Waiting for someone who holds <code>{a().capability}</code> in its namespace to decide it from a
                                browser session.
                            </p>
                        </Show>
                        <Show when={a().resultStatus}>
                            {(s) => (
                                <p class="mb-0">
                                    Ran <Show when={a().executedAt}>{(t) => <TimestampCell iso={t()} />}</Show> and returned{" "}
                                    <strong>{s()}</strong>.
                                </p>
                            )}
                        </Show>
                        <p class="mt-4 mb-0 text-sm">
                            <A href="/admin/agents">All agent keys and requests</A>
                        </p>
                    </Card>
                )}
            </QueryBoundary>
        </>
    );
}
