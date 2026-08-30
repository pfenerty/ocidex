import { For, Show, createMemo, createSignal, type JSX } from "solid-js";
import {
    APIClientError,
    type Namespace,
    type NamespaceMember as Member,
    type NamespaceRole,
} from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Button, Card, CardHeader, FormField } from "~/components/ui";
import { useToast } from "~/context/toast";
import { useAuth } from "~/context/auth";
import {
    useListUsers,
    useNamespaceMembers,
    useRemoveNamespaceMember,
    useSetNamespaceMember,
} from "~/api/queries";

/**
 * The roles a namespace member can hold (ADR-046), most privileged first. The
 * list is duplicated from `internal/authz` rather than derived from the schema
 * because the generated enum is a union type, not a value — there is nothing to
 * iterate at runtime. The conformance test that keeps them in step is on the Go
 * side; here the selector simply has to offer every role the API accepts.
 */
const ROLES: NamespaceRole[] = ["owner", "maintainer", "security", "developer", "viewer"];

/**
 * memberLabel prefers the username, falling back to the id. The username is
 * joined in by the API from the user table and comes back empty if that lookup
 * fails, which is not a reason to render a nameless row.
 */
function memberLabel(m: { username: string; user_id: string }): string {
    return m.username !== "" ? m.username : m.user_id;
}

/**
 * canManageMembers is the client-side mirror of `CapManageMember`, which only
 * `owner` and installation admins hold. It gates whether this panel renders at
 * all: the members endpoints answer 403 to everyone else, so showing a disabled
 * editor would advertise a surface the caller can never use.
 *
 * It is a UI affordance, not the authorization decision — that is the
 * `RequireCapability(manage_member)` middleware on the route. A caller who
 * defeats this check gets a 403, not access.
 */
function canManageMembers(role: string | undefined, userID: string | undefined, ns: Namespace): boolean {
    if (role === "admin") return true;
    return userID !== undefined && ns.owner_id === userID;
}

/**
 * NamespaceMembers is the roster editor for one namespace: who is a member and
 * with which role.
 *
 * It lives beside NamespacesTab rather than on a namespace detail page because
 * there is no namespace detail page — namespaces are a table under /admin. The
 * panel is opened from a row and rendered below the table.
 */
export function NamespaceMembers(props: { namespace: Namespace; onClose: () => void }): JSX.Element {
    const { user } = useAuth();
    const toast = useToast();

    const allowed = createMemo(() =>
        canManageMembers(user()?.role, user()?.id, props.namespace),
    );

    const members = useNamespaceMembers(
        () => props.namespace.id,
        { enabled: allowed },
    );
    const users = useListUsers();
    const setMember = useSetNamespaceMember();
    const removeMember = useRemoveNamespaceMember();

    const [addUserID, setAddUserID] = createSignal("");
    const [addRole, setAddRole] = createSignal<NamespaceRole>("viewer");

    // Only users who are not already members can be added; changing an existing
    // member's role is the row selector's job, not this form's.
    const candidates = createMemo(() => {
        const taken = new Set((members.data?.data ?? []).map((m) => m.user_id));
        return (users.data?.users ?? []).filter((u) => !taken.has(u.id));
    });

    function reportFailure(err: unknown, fallback: string) {
        if (err instanceof APIClientError && err.status === 409) {
            toast("A namespace has exactly one owner — transfer it instead", "error");
            return;
        }
        toast(fallback, "error");
    }

    function changeRole(userID: string, role: NamespaceRole) {
        setMember.mutate(
            { id: props.namespace.id, userID, role },
            {
                onSuccess: () => toast("Role updated", "success"),
                onError: (err) => reportFailure(err, "Failed to update role"),
            },
        );
    }

    function handleAdd(e: Event) {
        e.preventDefault();
        const userID = addUserID();
        if (userID === "") return;
        setMember.mutate(
            { id: props.namespace.id, userID, role: addRole() },
            {
                onSuccess: () => {
                    setAddUserID("");
                    setAddRole("viewer");
                    toast("Member added", "success");
                },
                onError: (err) => reportFailure(err, "Failed to add member"),
            },
        );
    }

    function handleRemove(userID: string, username: string) {
        if (!confirm(`Remove ${username} from "${props.namespace.name}"?`)) return;
        removeMember.mutate(
            { id: props.namespace.id, userID },
            {
                onSuccess: () => toast("Member removed", "success"),
                onError: (err) => reportFailure(err, "Failed to remove member"),
            },
        );
    }

    const columns: Column<Member>[] = [
        {
            header: "User",
            sortKey: "user",
            sortValue: memberLabel,
            render: (m) => <span>{memberLabel(m)}</span>,
        },
        {
            header: "Role",
            sortKey: "role",
            sortValue: (m) => m.role,
            // The owner row is fixed: the API refuses to demote the last owner
            // (409), so offering the control would be a lie.
            render: (m) => (
                <Show when={m.role !== "owner"} fallback={<span class="badge">owner</span>}>
                    <select
                        aria-label={`Role for ${memberLabel(m)}`}
                        value={m.role}
                        disabled={setMember.isPending}
                        onChange={(e) => changeRole(m.user_id, e.currentTarget.value as NamespaceRole)}
                    >
                        <For each={ROLES}>{(r) => <option value={r}>{r}</option>}</For>
                    </select>
                </Show>
            ),
        },
        {
            header: "Capabilities",
            class: "text-muted",
            render: (m) => <>{(m.capabilities ?? []).join(", ")}</>,
        },
        {
            header: "",
            render: (m) => (
                <Show when={m.role !== "owner"}>
                    <Button
                        size="sm"
                        variant="danger"
                        disabled={removeMember.isPending}
                        onClick={() => handleRemove(m.user_id, memberLabel(m))}
                    >
                        Remove
                    </Button>
                </Show>
            ),
        },
    ];

    return (
        <Show when={allowed()}>
            <Card class="mb-4" data-testid="namespace-members">
                <CardHeader
                    title={`Members of ${props.namespace.name}`}
                    count={members.data?.data.length}
                    actions={
                        <Button size="sm" onClick={props.onClose}>
                            Close
                        </Button>
                    }
                />

                <DataTable
                    bare
                    columns={columns}
                    rows={members.data?.data}
                    loading={members.isFetching}
                    isError={members.isError}
                    error={members.error}
                    emptyTitle="No members"
                    emptyMessage="Only the owner can reach this namespace until someone is added."
                />

                <form
                    onSubmit={handleAdd}
                    style={{
                        display: "flex",
                        gap: "0.75rem",
                        "align-items": "flex-end",
                        "flex-wrap": "wrap",
                        "margin-top": "1rem",
                    }}
                >
                    <FormField label="Add member">
                        <select
                            aria-label="User to add"
                            value={addUserID()}
                            onChange={(e) => setAddUserID(e.currentTarget.value)}
                        >
                            <option value="">Select a user…</option>
                            <For each={candidates()}>
                                {(u) => <option value={u.id}>{u.display_name}</option>}
                            </For>
                        </select>
                    </FormField>
                    <FormField label="Role">
                        <select
                            aria-label="Role to grant"
                            value={addRole()}
                            onChange={(e) => setAddRole(e.currentTarget.value as NamespaceRole)}
                        >
                            <For each={ROLES}>{(r) => <option value={r}>{r}</option>}</For>
                        </select>
                    </FormField>
                    <Button
                        variant="primary"
                        type="submit"
                        disabled={setMember.isPending || addUserID() === ""}
                    >
                        Add
                    </Button>
                </form>
            </Card>
        </Show>
    );
}
