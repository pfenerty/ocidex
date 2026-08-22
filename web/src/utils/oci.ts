// Helper utilities for OCI metadata display.

/** Returns true if the URL points to GitHub. */
export function isGitHubUrl(url: string): boolean {
  try {
    return new URL(url).hostname === "github.com";
  } catch {
    return false;
  }
}

/** Extracts "org/repo" from a GitHub URL. */
export function gitHubShortName(url: string): string | null {
  try {
    const { hostname, pathname } = new URL(url);
    if (hostname !== "github.com") return null;
    const parts = pathname.replace(/^\//, "").split("/");
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
    return null;
  } catch {
    return null;
  }
}

/** Builds a GitHub commit permalink from a source URL and revision SHA. */
export function gitHubCommitUrl(
  sourceUrl: string,
  revision: string,
): string | null {
  const short = gitHubShortName(sourceUrl);
  if (short === null) return null;
  return `https://github.com/${short}/commit/${revision}`;
}

/**
 * Returns a browsable registry URL for a container image name.
 * Handles Docker Hub, ghcr.io, quay.io, and falls back to a generic HTTPS URL.
 */
export function containerRegistryUrl(imageName: string): string {
  // Strip tag/digest suffix.
  const bare = imageName.replace(/@sha256:[a-f0-9]+$/, "").replace(/:[^/]+$/, "");

  // Docker Hub official images (no slash or "library/xxx").
  if (!bare.includes("/") || bare.startsWith("library/")) {
    const name = bare.replace(/^library\//, "");
    return `https://hub.docker.com/_/${name}`;
  }

  // Docker Hub with org (no dots in first segment → no registry host).
  const firstSeg = bare.split("/")[0];
  if (!firstSeg.includes(".")) {
    return `https://hub.docker.com/r/${bare}`;
  }

  // docker.io with explicit prefix
  if (firstSeg === "docker.io") {
    const path = bare.replace(/^docker\.io\//, "");
    if (path.startsWith("library/")) {
      return `https://hub.docker.com/_/${path.replace(/^library\//, "")}`;
    }
    return `https://hub.docker.com/r/${path}`;
  }

  // Red Hat registries
  if (firstSeg === "registry.access.redhat.com" || firstSeg === "registry.redhat.io") {
    const path = bare.replace(/^[^/]+\//, "");
    return `https://catalog.redhat.com/software/containers/${path}`;
  }

  // ghcr.io
  if (firstSeg === "ghcr.io") {
    const path = bare.replace(/^ghcr\.io\//, "");
    return `https://github.com/${path}/pkgs/container/${path.split("/").pop()}`;
  }

  // quay.io
  if (firstSeg === "quay.io") {
    const path = bare.replace(/^quay\.io\//, "");
    return `https://quay.io/repository/${path}`;
  }

  // Generic OCI registry — just link to https://host/path.
  return `https://${bare}`;
}

/**
 * Returns a registry key for a container image name:
 * "dockerhub", "ghcr", "quay", "redhat", or "oci" (default).
 */
export function detectRegistry(imageName: string): string {
  const bare = imageName.replace(/@sha256:[a-f0-9]+$/, "").replace(/:[^/]+$/, "");
  const firstSeg = bare.split("/")[0];

  // Docker Hub: no slash, library/*, no dots in first segment, or docker.io prefix
  if (!bare.includes("/") || bare.startsWith("library/") || !firstSeg.includes(".") || firstSeg === "docker.io") {
    return "dockerhub";
  }
  if (firstSeg === "ghcr.io") return "ghcr";
  if (firstSeg === "quay.io") return "quay";
  if (firstSeg === "registry.access.redhat.com" || firstSeg === "registry.redhat.io") return "redhat";
  return "oci";
}

/** Returns a friendly short display string for a URL. */
export function friendlyUrlDisplay(url: string): string {
  const gh = gitHubShortName(url);
  if (gh !== null) return gh;
  try {
    const u = new URL(url);
    const path = u.pathname.replace(/\/$/, "");
    return path ? `${u.hostname}${path}` : u.hostname;
  } catch {
    return url;
  }
}

const BARE_IMAGE_ID = /^(sha256:)?[0-9a-fA-F]{64}$/;

/**
 * Returns the human-readable name in an image reference, or null when the
 * reference names nothing.
 *
 * The k8s agent already prefers the pod spec's image when the runtime reports a
 * bare local image ID, so a null here means neither source had a name — a node
 * runtime gap, not something the reader can look up. Printing the raw value
 * would put 71 characters of hex in a table cell that promises a name.
 */
export function imageRefName(ref: string): string | null {
    const trimmed = ref.trim();
    if (trimmed === "" || BARE_IMAGE_ID.test(trimmed)) return null;
    return trimmed;
}

/**
 * Splits an image reference into the part a reader scans for and the part that
 * only disambiguates it.
 *
 * `registry.example.com/team/platform/api-gateway:v2.14.1` is 52 characters of
 * which the last 22 are what anyone is actually reading; rendering the leading
 * path muted keeps the whole ref present — truncating it would hide the
 * registry host, which is exactly what the Gaps tab needs a reader to notice.
 *
 * Returns null for a ref that names nothing, on the same grounds as
 * `imageRefName`.
 */
export function splitImageRef(ref: string): { prefix: string; name: string } | null {
    const named = imageRefName(ref);
    if (named === null) return null;
    const cut = named.lastIndexOf("/");
    if (cut === -1) return { prefix: "", name: named };
    return { prefix: named.slice(0, cut + 1), name: named.slice(cut + 1) };
}
