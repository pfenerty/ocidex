import { Router, Route } from "@solidjs/router";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import { AuthProvider } from "~/context/auth";
import { ToastProvider } from "~/context/toast";
import Layout from "~/components/Layout";
import Home from "~/pages/Home";
import Artifacts from "~/pages/Artifacts";
import ArtifactDetail from "~/pages/ArtifactDetail";
import ArtifactVersionHistory from "~/pages/ArtifactVersionHistory";
import SBOMDetail from "~/pages/SBOMDetail";
import Components from "~/pages/Components";
import ComponentOverview from "~/pages/ComponentOverview";
import ComponentDetail from "~/pages/ComponentDetail";
import Licenses from "~/pages/Licenses";
import LicenseComponents from "~/pages/LicenseComponents";
import Diff from "~/pages/Diff";
import Login from "~/pages/Login";
import Admin from "~/pages/Admin";
import NotFound from "~/pages/NotFound";

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 30_000,
            retry: 1,
            refetchOnWindowFocus: false,
        },
    },
});

export default function App() {
    return (
        <QueryClientProvider client={queryClient}>
            <ToastProvider>
            <AuthProvider>
            <Router root={Layout}>
                <Route path="/" component={Home} />
                <Route path="/artifacts" component={Artifacts} />
                <Route path="/artifacts/:id" component={ArtifactDetail} />
                <Route path="/artifacts/:id/versions/:version" component={ArtifactVersionHistory} />
                <Route path="/sboms/:id" component={SBOMDetail} />
                <Route path="/components" component={Components} />
                <Route
                    path="/components/overview"
                    component={ComponentOverview}
                />
                <Route path="/components/:id" component={ComponentDetail} />
                <Route path="/licenses" component={Licenses} />
                <Route
                    path="/licenses/:id/components"
                    component={LicenseComponents}
                />
                <Route path="/diff" component={Diff} />
                <Route path="/admin" component={Admin} />
                <Route path="/admin/keys" component={Admin} />
                <Route path="/admin/registries" component={Admin} />
                <Route path="/admin/status" component={Admin} />
                <Route path="/login" component={Login} />
                <Route path="*404" component={NotFound} />
            </Router>
            </AuthProvider>
            </ToastProvider>
        </QueryClientProvider>
    );
}
