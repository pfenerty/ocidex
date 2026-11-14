import { Task, nu, PAC_PARAMS } from "@tektonic-ci/core";
import { nodeImage, nodeCacheWs, nodeEnv, statusReporter, sourceWs } from "../../shared";
import { gitSafeCwd, nodeSetup } from "../../script-lib";
import { ghRelease } from "../gh-release/spec";

// The public docs site (ADR-0057): an Astro Starlight build in site/, its own npm package.
const siteModulesCache = {
  name: "site-node-modules",
  key: ["package-lock.json"],
  paths: ["node_modules"],
  workspace: nodeCacheWs,
  compress: true,
  workingDir: sourceWs.at("site"),
};

const resources = {
  limits: { cpu: "2", memory: "2Gi" },
  requests: { cpu: "500m", memory: "1Gi" },
};

// PR: build the site. starlight-links-validator fails the build on a broken internal link,
// and `npm run check` fails on a stale generated reference page.
export const docsBuild = new Task({
  name: "docs-build",
  statusReporter,
  caches: [siteModulesCache],
  stepTemplate: { env: nodeEnv },
  steps: [
    {
      name: "docs-build",
      image: nodeImage,
      workingDir: sourceWs.at("site"),
      computeResources: resources,
      script: nu`
${nodeSetup}
log "Building the docs site (link check included)"
^npm run build
log "OK: docs site built"
`,
    },
  ],
});

// Publish to the gh-pages branch, which GitHub Pages serves at docs.ocidex.app.
// "release" (tag pipeline) replaces everything but next/; "next" (push to main) replaces
// only next/. The push uses github-pipeline-token, the PAT gh-release already holds.
function docsPublish(name: string, channel: "release" | "next", needs: Task[] = []) {
  return new Task({
    name,
    statusReporter,
    needs,
    caches: [siteModulesCache],
    stepTemplate: { env: nodeEnv },
    steps: [
      {
        name: "docs-publish",
        image: nodeImage,
        workingDir: sourceWs.at("site"),
        computeResources: resources,
        env: [
          { name: "DOCS_CHANNEL", value: channel },
          {
            name: "GH_TOKEN",
            valueFrom: { secretKeyRef: { name: "github-pipeline-token", key: "token" } },
          },
        ],
        script: nu`
${nodeSetup}
${gitSafeCwd}
let channel = $env.DOCS_CHANNEL
let base = if $channel == "next" { "/next/" } else { "/" }
log $"Building the docs site for ($channel) at base ($base)"
with-env {DOCS_BASE: $base} { ^npm run build }

# The token travels as an auth header from git's env config, never in a URL or argv.
let auth = ($"x-access-token:($env.GH_TOKEN)" | encode base64)
$env.GIT_CONFIG_COUNT = "1"
$env.GIT_CONFIG_KEY_0 = "http.https://github.com/.extraheader"
$env.GIT_CONFIG_VALUE_0 = $"AUTHORIZATION: basic ($auth)"
let remote = "https://github.com/$(params.repo-full-name).git"
let site = (pwd)
let pages = "/tmp/gh-pages"

# A tag run and a main run can race on the branch: on a rejected push, start over from
# the new tip and re-apply, so neither channel's update is lost.
mut attempt = 1
loop {
  rm -rf $pages
  if (^git ls-remote --heads $remote gh-pages | str trim | is-empty) {
    ^git init -q -b gh-pages $pages
    ^git -C $pages remote add origin $remote
  } else {
    ^git clone -q --depth 1 --branch gh-pages $remote $pages
  }
  if $channel == "next" {
    rm -rf $"($pages)/next"
    cp -r $"($site)/dist" $"($pages)/next"
  } else {
    ls -a $pages | where {|e| ($e.name | path basename) not-in [".git" "next"] } | each {|e| rm -rf $e.name } | ignore
    ls -a $"($site)/dist" | each {|e| cp -r $e.name $pages } | ignore
  }
  "docs.ocidex.app\n" | save -f $"($pages)/CNAME"
  "" | save -f $"($pages)/.nojekyll"

  ^git -C $pages add -A
  if (^git -C $pages status --porcelain | str trim | is-empty) {
    log "OK: gh-pages already up to date"
    break
  }
  (^git -C $pages -c user.name=ocidex-ci -c user.email=ocidex-ci@users.noreply.github.com
    commit -q -m $"docs: publish ($channel) from ${PAC_PARAMS.revision}")
  let push = (do { ^git -C $pages push -q origin gh-pages } | complete)
  if $push.exit_code == 0 {
    log $"OK: published ($channel) docs"
    break
  }
  if $attempt >= 3 { error make { msg: $"push to gh-pages failed: ($push.stderr)" } }
  log $"push rejected, retrying: attempt ($attempt) of 3"
  $attempt += 1
}
`,
      },
    ],
  });
}

export const docsPublishNext = docsPublish("docs-publish-next", "next");
// After gh-release, so the release docs never go live ahead of the release they describe.
export const docsPublishRelease = docsPublish("docs-publish-release", "release", [ghRelease]);
