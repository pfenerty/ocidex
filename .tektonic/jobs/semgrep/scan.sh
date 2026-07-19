#!/bin/sh
# Report-only SAST. `--error` makes semgrep exit non-zero on findings so the check
# reflects them (pipeline stays green via onError: continue). Metrics/version checks
# are disabled for hermetic, quiet runs.
semgrep scan --error --disable-version-check --metrics off \
  --jobs 1 --max-memory 2048 \
  --config p/golang \
  --config p/typescript \
  --config p/secrets \
  .
