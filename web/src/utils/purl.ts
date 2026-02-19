// PURL (Package URL) utilities for generating registry links.

interface PurlParts {
  type: string;
  namespace?: string;
  name: string;
  version?: string;
}

/** Parse a PURL string into its constituent parts. */
export function parsePurl(purl: string): PurlParts | null {
  // Format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
  const match = purl.match(/^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:\?[^#]*)?(?:#.*)?$/);
  if (!match) return null;

  const [, type, path, version] = match;
  const segments = path.split("/");
  const name = segments.pop()!;
  const namespace = segments.length > 0 ? segments.join("/") : undefined;

  return { type, namespace, name, version };
}

/** Registry URL mappings by PURL type. */
const registryMap: Record<string, (p: PurlParts) => string | null> = {
  npm: (p) => {
    const pkg = p.namespace ? `${p.namespace}/${p.name}` : p.name;
    return p.version
      ? `https://www.npmjs.com/package/${pkg}/v/${p.version}`
      : `https://www.npmjs.com/package/${pkg}`;
  },
  pypi: (p) =>
    p.version
      ? `https://pypi.org/project/${p.name}/${p.version}/`
      : `https://pypi.org/project/${p.name}/`,
  golang: (p) => {
    const mod = p.namespace ? `${p.namespace}/${p.name}` : p.name;
    return p.version
      ? `https://pkg.go.dev/${mod}@${p.version}`
      : `https://pkg.go.dev/${mod}`;
  },
  maven: (p) =>
    p.namespace
      ? `https://search.maven.org/artifact/${p.namespace}/${p.name}/${p.version ?? ""}`
      : null,
  gem: (p) =>
    p.version
      ? `https://rubygems.org/gems/${p.name}/versions/${p.version}`
      : `https://rubygems.org/gems/${p.name}`,
  cargo: (p) =>
    p.version
      ? `https://crates.io/crates/${p.name}/${p.version}`
      : `https://crates.io/crates/${p.name}`,
  nuget: (p) =>
    p.version
      ? `https://www.nuget.org/packages/${p.name}/${p.version}`
      : `https://www.nuget.org/packages/${p.name}`,
  deb: (p) =>
    `https://packages.debian.org/search?keywords=${p.name}`,
  apk: (p) =>
    `https://pkgs.alpinelinux.org/packages?name=${p.name}`,
  rpm: (p) =>
    `https://src.fedoraproject.org/rpms/${p.name}`,
  hackage: (p) =>
    `https://hackage.haskell.org/package/${p.name}`,
  hex: (p) =>
    `https://hex.pm/packages/${p.name}`,
  cocoapods: (p) =>
    `https://cocoapods.org/pods/${p.name}`,
  composer: (p) =>
    p.namespace
      ? `https://packagist.org/packages/${p.namespace}/${p.name}`
      : null,
  swift: (p) =>
    p.namespace
      ? `https://swiftpackageindex.com/${p.namespace}/${p.name}`
      : null,
};

/** Get the external registry URL for a PURL, or null if unsupported. */
export function purlToRegistryUrl(purl: string): string | null {
  const parts = parsePurl(purl);
  if (!parts) return null;
  const builder = registryMap[parts.type];
  return builder ? builder(parts) : null;
}

/** Human-friendly display name: namespace/name@version (no type prefix or qualifiers). */
export function purlDisplayName(purl: string): string {
  const parts = parsePurl(purl);
  if (!parts) return purl;
  const pkg = parts.namespace ? `${parts.namespace}/${parts.name}` : parts.name;
  return parts.version ? `${pkg}@${parts.version}` : pkg;
}

/** Get a human-readable label for a PURL type. */
export function purlTypeLabel(purl: string): string | null {
  const parts = parsePurl(purl);
  if (!parts) return null;

  const labels: Record<string, string> = {
    npm: "npm",
    pypi: "PyPI",
    golang: "Go",
    maven: "Maven",
    gem: "RubyGems",
    cargo: "Crates.io",
    nuget: "NuGet",
    deb: "Debian",
    apk: "Alpine",
    rpm: "RPM",
    hackage: "Hackage",
    hex: "Hex",
    cocoapods: "CocoaPods",
    composer: "Packagist",
    swift: "SwiftPM",
    oci: "OCI",
  };

  return labels[parts.type] ?? parts.type;
}
