import {
    createContext,
    createResource,
    useContext,
    type ParentProps,
    type ResourceReturn,
} from "solid-js";
import { API_BASE_URL } from "~/api/client";

interface User {
    id: string;
    github_username: string;
    role: string;
}

interface AuthContextValue {
    user: ResourceReturn<User | undefined>[0];
    refetch: ResourceReturn<User | undefined>[1]["refetch"];
}

const AuthContext = createContext<AuthContextValue>();

async function fetchMe(): Promise<User | undefined> {
    const res = await fetch(`${API_BASE_URL}/auth/me`, { credentials: "include" });
    if (res.status === 401) return undefined;
    if (!res.ok) return undefined;
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
