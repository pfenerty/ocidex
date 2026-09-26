import * as path from "path";
import { Task, scriptFromFile } from "@tektonic-ci/core";
import { goImage, statusReporter } from "../../shared";

export const goFmt = new Task({
  name: "gofmt-check",
  statusReporter,
  steps: [
    {
      name: "gofmt-check",
      image: goImage,
      script: scriptFromFile(path.join(__dirname, "fmt.nu")),
    },
  ],
});
