#!/bin/sh
# Report-only secrets scan of the working tree. `--no-git` scans files directly so
# it works regardless of clone depth; gitleaks exits non-zero when a leak is found,
# which the statusReporter surfaces as a failed check (pipeline stays green via
# onError: continue).
gitleaks detect --source . --config .gitleaks.toml --no-git --redact --verbose
