import { depScanTask } from "../_dep-scan";

// Node/TS dependency vuln scan for the SolidJS frontend. Previously the frontend's deps
// were never vuln-scanned (frontend-lint runs eslint only). syft catalogs the npm graph
// straight from the lockfile (no install, no network) → grype → SARIF. Report-only.
export const webSecurity = depScanTask({
  name: "web-security",
  source: "file:web/package-lock.json",
  sbom: "sbom-web.json",
  category: "grype-web",
});
