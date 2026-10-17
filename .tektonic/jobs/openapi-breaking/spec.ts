import * as path from "path";
import { Task, scriptFromFile } from "@tektonic-ci/core";
import { statusReporter, sourceWs } from "../../shared";

// Breaking-change gate for /api/v1 (ADR-052, ocidex-tkn9.3): oasdiff compares the PR's
// committed spec with the spec at the latest release tag. Pinned by digest; the image is
// alpine + git + oasdiff, so one sh step does the tag fetch and the diff.
const oasdiffImage =
  "docker.io/tufin/oasdiff:v1.33.0@sha256:6263a96dd2ef0726c54e21fea9b8e1607eac4841add0079324b424c1f52b819c";

export const openapiBreaking = new Task({
  name: "openapi-breaking",
  statusReporter,
  steps: [
    {
      name: "oasdiff-breaking",
      image: oasdiffImage,
      workingDir: sourceWs.path,
      onError: "continue",
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "100m", memory: "128Mi" },
      },
      script: scriptFromFile(path.join(__dirname, "check.sh")),
    },
  ],
});
