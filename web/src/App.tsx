import { Router, Route, Navigate } from "@solidjs/router";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import Layout from "~/components/Layout";
import Artifacts from "~/pages/Artifacts";
import ArtifactDetail from "~/pages/ArtifactDetail";
import SBOMDetail from "~/pages/SBOMDetail";
import Components from "~/pages/Components";
import ComponentOverview from "~/pages/ComponentOverview";
import ComponentDetail from "~/pages/ComponentDetail";
import Licenses from "~/pages/Licenses";
import LicenseComponents from "~/pages/LicenseComponents";
import Diff from "~/pages/Diff";
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
            <Router root={Layout}>
                <Route
                    path="/"
                    component={() => <Navigate href="/artifacts" />}
                />
                <Route path="/artifacts" component={Artifacts} />
                <Route path="/artifacts/:id" component={ArtifactDetail} />
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
                <Route path="*404" component={NotFound} />
            </Router>
        </QueryClientProvider>
    );
}
