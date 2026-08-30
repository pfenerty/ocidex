import {
    createContext,
    createResource,
    useContext,
    type ParentProps,
    type ResourceReturn,
} from "solid-js";
import { API_BASE_URL } from "~/api/client";
import type { Membership } from "~/utils/emphasis";

interface User {
    id: string;
    display_name: string;
    role: string;
    /**
     * The caller's namespace memberships, as /users/me reports them. Present
     * so the UI can emphasise what this kind of user came for (see
     * ~/utils/emphasis) — it is never an authorization input, and it is
     * optional because a client running against an older server will not get
     * the field at all.
     */
    memberships?: Membership[];
}

interface AuthContextValue {
    user: ResourceReturn<User | undefined>[0];
    refetch: ResourceReturn<User | undefined>[1]["refetch"];
}

const AuthContext = createContext<AuthContextValue>();

async function fetchMe(): Promise<User | undefined> {
    const res = await fetch(`${API_BASE_URL}/api/v1/users/me`, { credentials: "include" });
    if (res.status === 401) return undefined;
    if (!res.ok) {
        console.error(`fetchMe: unexpected HTTP ${res.status}`);
        return undefined;
    }
    const data: unknown = await res.json();
    return data as User;
}

export function AuthProvider(props: ParentProps) {
    const [user, { refetch }] = createResource(fetchMe);
    return (
        <AuthContext.Provider value={{ user, refetch }}>
            {props.children}
        </AuthContext.Provider>
    );
}

export function useAuth(): AuthContextValue {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
    return ctx;
}
