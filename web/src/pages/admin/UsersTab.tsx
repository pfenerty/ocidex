import { Show, createSignal } from "solid-js";
import { useAuth } from "~/context/auth";
import { useToast } from "~/context/toast";
import { Loading, ErrorBox } from "~/components/Feedback";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { UserAccount } from "~/api/client";
import { useListUsers, useUpdateUserRole } from "~/api/queries";

type Role = "admin" | "member" | "viewer";

export function UsersTab() {
    const { user: currentUser } = useAuth();
    const query = useListUsers();
    const updateRole = useUpdateUserRole();
    const toast = useToast();
    const [overrides, setOverrides] = createSignal<Record<string, Role>>({});

    const roleFor = (u: UserAccount) => overrides()[u.id] ?? (u.role as Role);

    const columns: Column<UserAccount>[] = [
        { header: "Username", render: (u) => <>{u.github_username}</> },
        {
            header: "Role",
            render: (u) => <span class="badge">{roleFor(u)}</span>,
        },
        {
            header: "Actions",
            render: (u) => {
                const isSelf = () => u.id === currentUser()?.id;
                return (
                    <select
                        value={roleFor(u)}
                        disabled={isSelf() || updateRole.isPending}
                        onChange={(e) => {
                            const newRole = e.currentTarget.value as Role;
                            setOverrides((prev) => ({ ...prev, [u.id]: newRole }));
                            updateRole.mutate({ id: u.id, role: newRole }, {
                                onSuccess: () => toast(`Role updated to ${newRole}`, "success"),
                                onError: () => toast("Failed to update role", "error"),
                            });
                        }}
                    >
                        <option value="admin">admin</option>
                        <option value="member">member</option>
                        <option value="viewer">viewer</option>
                    </select>
                );
            },
        },
    ];

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <DataTable
                    columns={columns}
                    rows={query.data?.users ?? undefined}
                    loading={false}
                    isError={false}
                    emptyTitle="No users found"
                />
            </Show>
        </Show>
    );
}
