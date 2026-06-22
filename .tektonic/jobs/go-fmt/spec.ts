import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { goImage, statusReporter } from "../../shared";

export const goFmt = new Task({
  name: "go-fmt",
  statusReporter,
  steps: [
    {
      name: "fmt",
      image: goImage,
      script: scriptFromFile(path.join(__dirname, "fmt.nu")),
    },
  ],
});
