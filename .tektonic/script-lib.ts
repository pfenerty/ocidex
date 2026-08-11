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

// Run a memory-hungry tool under a cgroup watchdog.
//
// A container that exceeds its memory limit is OOMKilled by the kernel, and Tekton treats that
// as an infrastructure failure rather than a script exit code — so it bypasses `onError:
// continue` entirely, hard-failing the TaskRun and PipelineRun despite a report-only design,
// and the report-status step never runs, leaving the GitHub check pending forever. The
// watchdog runs the tool as a child process while polling this cgroup's own memory.current
// against memory.max, and self-terminates the child at 92% — converting a would-be OOMKill
// into an ordinary exit 99 that `onError: continue` and `failOnError: false` already handle.
//
// `command` is POSIX sh, not nushell: it runs under `sh -c`. Anything the caller needs to pass
// from nushell goes through `args` (a nushell expression, e.g. `...$baseline`) and is read back
// as `"$@"` inside `command` — the watchdog body is a raw string, so nushell interpolation is
// unavailable there by design (it also carries `$pid`, `$cur` and friends verbatim).
//
// Proven on govulncheck-scan first (ocidex-2w2), lifted here for semgrep-sast (ocidex-im4o.3).
export function memoryWatchdog(label: string, command: string, args = ""): string {
  return `let watchdog = r#'
${command} &
pid=$!
max_file=/sys/fs/cgroup/memory.max
cur_file=/sys/fs/cgroup/memory.current
[ -f "$max_file" ] || max_file=/sys/fs/cgroup/memory/memory.limit_in_bytes
[ -f "$cur_file" ] || cur_file=/sys/fs/cgroup/memory/memory.usage_in_bytes
mem_max=$(cat "$max_file" 2>/dev/null || echo 0)
if [ "$mem_max" != "max" ] && [ "$mem_max" -gt 0 ] 2>/dev/null; then
  threshold=$((mem_max * 92 / 100))
  while kill -0 "$pid" 2>/dev/null; do
    cur=$(cat "$cur_file" 2>/dev/null || echo 0)
    if [ "$cur" -gt "$threshold" ] 2>/dev/null; then
      echo "${label}: usage $cur bytes exceeded 92% of cgroup limit $mem_max - self-terminating before kernel OOM-kill" >&2
      kill -TERM "$pid" 2>/dev/null
      sleep 2
      kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      exit 99
    fi
    sleep 1
  done
fi
wait "$pid"
'#
^sh -c $watchdog ${label}${args ? ` ${args}` : ""}`;
}

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
