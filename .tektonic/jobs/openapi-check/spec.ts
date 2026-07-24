import { Task, nu } from "@pfenerty/tektonic";
import { goImage, nodeImage, goEnv, nodeEnv, statusReporter } from "../../shared";
import { goSetup, nodeSetup } from "../../script-lib";
import { goBuild } from "../go-build/spec";
import { frontendLint } from "../frontend-lint/spec";

// Verify the committed OpenAPI spec + generated TS types are up to date. check-spec regenerates
// the spec from Go (go run ./cmd/specgen) and diffs it; check-types regenerates the TS types
// from the spec and diffs those. Cross-language, hence the goBuild + frontendLint needs
// (cache-warm ordering; neither consumes their artifacts).
export const openapiCheck = new Task({
  name: "openapi-verify",
  needs: [goBuild, frontendLint],
  statusReporter,
  stepTemplate: {
    env: [...goEnv, ...nodeEnv],
  },
  steps: [
    {
      name: "openapi-spec-check",
      image: goImage,
      script: nu`
${goSetup}
log "Generating OpenAPI spec"
^go run ./cmd/specgen out> /tmp/openapi-check.json
log "Diffing against committed spec"
^diff web/openapi.json /tmp/openapi-check.json
log "OK: spec is up to date"
`,
      onError: "continue",
    },
    {
      name: "openapi-types-check",
      image: nodeImage,
      workingDir: "$(workspaces.workspace.path)/web",
      computeResources: {
        limits: { cpu: "2", memory: "3Gi" },
        requests: { cpu: "100m", memory: "2Gi" },
      },
      // No manual prev-exit-code handling: synth's exit-code contract keeps the worst code
      // across both steps, so a check-spec failure propagates even if check-types passes.
      script: nu`
${nodeSetup}
log "Generating TypeScript types from spec"
^npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts
log "Diffing against committed types"
^diff src/types/openapi.d.ts /tmp/openapi-check.d.ts
log "OK: types up to date"
`,
      onError: "continue",
    },
  ],
});
