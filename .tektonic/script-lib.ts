// Shared nushell snippets for job scripts, interpolated into tektonic `nu` templates
// flush-left (column 0) so the tag's dedent leaves them clean. They assume the consuming step
// runs one of our apko images (which all ship nushell — including the semgrep/gitleaks images
// now) and has a statusReporter (so the injected `log` helper exists) — true for every task.

// Mark the root-owned checkout (local-path PV) safe for git — steps run as uid 1024, which
// has no /etc/passwd entry, so git otherwise refuses with "dubious ownership".
export const gitSafeCwd = `^git config --global --add safe.directory (pwd)`;

// Go step preamble: log toolchain + uid, then mark the checkout safe for git.
export const goSetup = `log $"go=(go version) uid=(id -u) pwd=(pwd)"
${gitSafeCwd}`;

// Node step preamble: log toolchain, then install deps. npm ci is idempotent and restores
// from the node_modules cache, so re-running it across steps/tasks is cheap.
export const nodeSetup = `log $"node=(node --version) npm=(npm --version) uid=(id -u)"
log "Installing dependencies (npm ci)"
^npm ci`;

// PAC diff-baseline for the report-only security scans (semgrep, gitleaks). Marks the whole
// tree safe (the tools shell out to git in subdirs), then — when PAC signals a pull_request
// with a known base branch — fetches that base into FETCH_HEAD. Leaves `$scoped` = true when
// a diff baseline is available, false for a full scan (push, unknown event, or fetch failure).
// A dedicated FETCH_HEAD avoids `$(git ...)` command substitution, which collides with
// Tekton's own `$(...)` variable syntax.
export const pacBaseline = `^git config --global --add safe.directory '*'
let pac_event = ($env.PAC_EVENT_TYPE? | default "")
let pac_target = ($env.PAC_TARGET_BRANCH? | default "")
mut scoped = false
if $pac_event == "pull_request" and ($pac_target | is-not-empty) {
  let fetched = (do { ^git -c safe.directory='*' fetch --quiet origin $pac_target } | complete)
  if $fetched.exit_code == 0 { $scoped = true }
}`;
