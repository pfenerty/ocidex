import { For, Show, createSignal } from "solid-js";
import { useAuth } from "~/context/auth";
import { useToast } from "~/context/toast";
import { Loading, ErrorBox } from "~/components/Feedback";
import { useListUsers, useUpdateUserRole } from "~/api/queries";

export function UsersTab() {
    const { user: currentUser } = useAuth();
    const query = useListUsers();
    const updateRole = useUpdateUserRole();
    const toast = useToast();

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div class="card">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={query.data?.users ?? []}>
                                    {(u) => {
                                        const isSelf = () => u.id === currentUser()?.id;
                                        const [role, setRole] = createSignal(u.role as "admin" | "member" | "viewer");
                                        return (
                                            <tr>
                                                <td>{u.github_username}</td>
                                                <td>
                                                    <span class="badge">{role()}</span>
                                                </td>
                                                <td>
                                                    <select
                                                        value={role()}
                                                        disabled={isSelf() || updateRole.isPending}
                                                        onChange={(e) => {
                                                            const newRole = e.currentTarget.value as "admin" | "member" | "viewer";
                                                            setRole(newRole);
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
                                                </td>
                                            </tr>
                                        );
                                    }}
                                </For>
                            </tbody>
                        </table>
                    </div>
                </div>
            </Show>
        </Show>
    );
}
