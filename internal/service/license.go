package service

import "strings"

type licenseDef struct {
	spdxID string
	name   string
}

// licenseAlias maps common non-SPDX license name variants (lowercased) to their
// canonical SPDX identifier and display name.
var licenseAlias = map[string]licenseDef{
	// MIT
	"mit":             {"MIT", "MIT License"},
	"mit license":     {"MIT", "MIT License"},
	"the mit license": {"MIT", "MIT License"},

	// Apache
	"apache 2.0":                      {"Apache-2.0", "Apache License 2.0"},
	"apache-2.0":                      {"Apache-2.0", "Apache License 2.0"},
	"apache license 2.0":              {"Apache-2.0", "Apache License 2.0"},
	"apache-2":                        {"Apache-2.0", "Apache License 2.0"},
	"asl 2.0":                         {"Apache-2.0", "Apache License 2.0"},
	"asl 1.1":                         {"Apache-1.1", "Apache Software License 1.1"},
	"apache 2":                        {"Apache-2.0", "Apache License 2.0"},
	"apache license":                  {"Apache-2.0", "Apache License 2.0"},
	"apache license, version 2.0":     {"Apache-2.0", "Apache License 2.0"},
	"the apache license, version 2.0": {"Apache-2.0", "Apache License 2.0"},
	"the apache software license, version 2.0": {"Apache-2.0", "Apache License 2.0"},

	// GPL-2.0
	"gplv2":            {"GPL-2.0-only", "GNU General Public License v2.0 only"},
	"gpl-2":            {"GPL-2.0-only", "GNU General Public License v2.0 only"},
	"gpl 2":            {"GPL-2.0-only", "GNU General Public License v2.0 only"},
	"gpl-2.0":          {"GPL-2.0-only", "GNU General Public License v2.0 only"},
	"gpl-2.0-only":     {"GPL-2.0-only", "GNU General Public License v2.0 only"},
	"gplv2+":           {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gpl-2.0+":         {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gpl-2+":           {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gpl 2+":           {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gpl-2-or-later":   {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gpl-2.0-or-later": {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},

	// GPL-3.0
	"gplv3":            {"GPL-3.0-only", "GNU General Public License v3.0 only"},
	"gpl-3":            {"GPL-3.0-only", "GNU General Public License v3.0 only"},
	"gpl 3":            {"GPL-3.0-only", "GNU General Public License v3.0 only"},
	"gpl-3.0":          {"GPL-3.0-only", "GNU General Public License v3.0 only"},
	"gpl-3.0-only":     {"GPL-3.0-only", "GNU General Public License v3.0 only"},
	"gplv3+":           {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},
	"gpl-3.0+":         {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},
	"gpl-3+":           {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},
	"gpl 3+":           {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},
	"gpl-3-or-later":   {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},
	"gpl-3.0-or-later": {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},

	// GPL (unversioned — default to 2.0-or-later)
	"gpl":  {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gpl+": {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},

	// LGPL
	"lgpl":              {"LGPL-2.1-or-later", "GNU Lesser General Public License v2.1 or later"},
	"lgplv2":            {"LGPL-2.0-only", "GNU Library General Public License v2 only"},
	"lgpl-2":            {"LGPL-2.0-only", "GNU Library General Public License v2 only"},
	"lgpl-2.0":          {"LGPL-2.0-only", "GNU Library General Public License v2 only"},
	"lgpl-2.0-only":     {"LGPL-2.0-only", "GNU Library General Public License v2 only"},
	"lgplv2+":           {"LGPL-2.0-or-later", "GNU Library General Public License v2 or later"},
	"lgpl-2+":           {"LGPL-2.0-or-later", "GNU Library General Public License v2 or later"},
	"lgpl-2.0-or-later": {"LGPL-2.0-or-later", "GNU Library General Public License v2 or later"},
	"lgplv2.1":          {"LGPL-2.1-only", "GNU Lesser General Public License v2.1 only"},
	"lgpl-2.1":          {"LGPL-2.1-only", "GNU Lesser General Public License v2.1 only"},
	"lgpl-2.1-only":     {"LGPL-2.1-only", "GNU Lesser General Public License v2.1 only"},
	"lgpl-2.1-or-later": {"LGPL-2.1-or-later", "GNU Lesser General Public License v2.1 or later"},
	"lgplv3":            {"LGPL-3.0-only", "GNU Lesser General Public License v3.0 only"},
	"lgpl-3":            {"LGPL-3.0-only", "GNU Lesser General Public License v3.0 only"},
	"lgpl-3.0":          {"LGPL-3.0-only", "GNU Lesser General Public License v3.0 only"},
	"lgpl-3.0-only":     {"LGPL-3.0-only", "GNU Lesser General Public License v3.0 only"},
	"lgplv3+":           {"LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later"},
	"lgpl-3+":           {"LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later"},
	"lgpl-3.0-or-later": {"LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later"},

	// AGPL
	"agplv3":            {"AGPL-3.0-only", "GNU Affero General Public License v3.0"},
	"agpl-3":            {"AGPL-3.0-only", "GNU Affero General Public License v3.0"},
	"agpl-3.0":          {"AGPL-3.0-only", "GNU Affero General Public License v3.0"},
	"agpl-3.0-only":     {"AGPL-3.0-only", "GNU Affero General Public License v3.0"},
	"agpl-3.0-or-later": {"AGPL-3.0-or-later", "GNU Affero General Public License v3.0 or later"},

	// BSD
	"bsd":                  {"BSD-3-Clause", "BSD 3-Clause License"},
	"bsd license":          {"BSD-3-Clause", "BSD 3-Clause License"},
	"bsd-3":                {"BSD-3-Clause", "BSD 3-Clause License"},
	"bsd-3-clause":         {"BSD-3-Clause", "BSD 3-Clause License"},
	"bsd 3-clause":         {"BSD-3-Clause", "BSD 3-Clause License"},
	"0bsd":                 {"0BSD", "BSD Zero Clause License"},
	"bsd-2":                {"BSD-2-Clause", "BSD 2-Clause \"Simplified\" License"},
	"bsd-2-clause":         {"BSD-2-Clause", "BSD 2-Clause \"Simplified\" License"},
	"bsd 2-clause":         {"BSD-2-Clause", "BSD 2-Clause \"Simplified\" License"},
	"bsd-4-clause":         {"BSD-4-Clause", "BSD 4-Clause \"Original\" License"},
	"bsd with advertising": {"BSD-4-Clause", "BSD 4-Clause \"Original\" License"},

	// MPL
	"mpl":     {"MPL-2.0", "Mozilla Public License 2.0"},
	"mpl-2":   {"MPL-2.0", "Mozilla Public License 2.0"},
	"mpl-2.0": {"MPL-2.0", "Mozilla Public License 2.0"},
	"mpl 2.0": {"MPL-2.0", "Mozilla Public License 2.0"},
	"mplv2.0": {"MPL-2.0", "Mozilla Public License 2.0"},

	// EPL / EDL
	"eclipse public license - v 2.0": {"EPL-2.0", "Eclipse Public License 2.0"},
	"epl-2.0":                        {"EPL-2.0", "Eclipse Public License 2.0"},
	"epl-1.0":                        {"EPL-1.0", "Eclipse Public License 1.0"},
	"edl 1.0":                        {"BSD-3-Clause", "Eclipse Distribution License v1.0"},

	// CDDL
	"cddl-1.0": {"CDDL-1.0", "Common Development and Distribution License 1.0"},
	"cddl-1.1": {"CDDL-1.1", "Common Development and Distribution License 1.1"},

	// ISC
	"isc":         {"ISC", "ISC License"},
	"isc license": {"ISC", "ISC License"},

	// Zlib
	"zlib license": {"Zlib", "zlib License"},
	"zlib":         {"Zlib", "zlib License"},

	// Boost
	"boost":                  {"BSL-1.0", "Boost Software License 1.0"},
	"boost software license": {"BSL-1.0", "Boost Software License 1.0"},
	"bsl-1.0":                {"BSL-1.0", "Boost Software License 1.0"},

	// Public domain / Unlicense / CC0
	"public domain": {"Unlicense", "The Unlicense"},
	"public-domain": {"Unlicense", "The Unlicense"},
	"publicdomain":  {"Unlicense", "The Unlicense"},
	"the unlicense": {"Unlicense", "The Unlicense"},
	"unlicense":     {"Unlicense", "The Unlicense"},
	"public domain, per creative commons cc0": {"CC0-1.0", "Creative Commons Zero v1.0 Universal"},
	"cc0-1.0": {"CC0-1.0", "Creative Commons Zero v1.0 Universal"},

	// GFDL
	"gfdl": {"GFDL-1.3-or-later", "GNU Free Documentation License v1.3 or later"},

	// Verbose display names that arrive as plain names
	"gnu general public license v2.0 only":                                {"GPL-2.0-only", "GNU General Public License v2.0 only"},
	"gnu general public license v2.0 or later":                            {"GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
	"gnu general public license v3.0 only":                                {"GPL-3.0-only", "GNU General Public License v3.0 only"},
	"gnu general public license v3.0 or later":                            {"GPL-3.0-or-later", "GNU General Public License v3.0 or later"},
	"gnu general public license, version 2, with the classpath exception": {"GPL-2.0-only WITH Classpath-exception-2.0", "GPL 2.0 with Classpath Exception"},

	// Known SPDX IDs that sometimes arrive as name-only
	"ssh-openssh":    {"SSH-OpenSSH", "SSH OpenSSH License"},
	"x11":            {"X11", "X11 License"},
	"openssl":        {"OpenSSL", "OpenSSL License"},
	"blessing":       {"blessing", "SQLite Blessing"},
	"curl":           {"curl", "curl License"},
	"oldap-2.8":      {"OLDAP-2.8", "Open LDAP Public License v2.8"},
	"bitstream vera": {"Bitstream-Vera", "Bitstream Vera Font License"},
	"bzip2-1.0.6":    {"bzip2-1.0.6", "bzip2 and libbzip2 License v1.0.6"},
	"w3c":            {"W3C", "W3C Software Notice and License"},
	"ftl":            {"FTL", "Freetype Project License"},
	"ijg":            {"IJG", "Independent JPEG Group License"},
	"rsa":            {"RSA-MD", "RSA Message-Digest License"},
}

// licenseURLs maps well-known license URLs (lowercased, trailing slash stripped)
// to SPDX identifiers.
var licenseURLs = map[string]licenseDef{
	// Apache
	"http://www.apache.org/licenses/license-2.0.txt":       {"Apache-2.0", "Apache License 2.0"},
	"https://www.apache.org/licenses/license-2.0.txt":      {"Apache-2.0", "Apache License 2.0"},
	"http://www.apache.org/licenses/license-2.0.html":      {"Apache-2.0", "Apache License 2.0"},
	"http://www.apache.org/licenses/license-2.0":           {"Apache-2.0", "Apache License 2.0"},
	"https://www.apache.org/licenses/license-2.0":          {"Apache-2.0", "Apache License 2.0"},
	"https://apache.org/licenses/license-2.0.txt":          {"Apache-2.0", "Apache License 2.0"},
	"http://repository.jboss.org/licenses/apache-2.0.txt":  {"Apache-2.0", "Apache License 2.0"},
	"https://repository.jboss.org/licenses/apache-2.0.txt": {"Apache-2.0", "Apache License 2.0"},

	// MIT
	"http://www.opensource.org/licenses/mit-license.php":  {"MIT", "MIT License"},
	"https://www.opensource.org/licenses/mit-license.php": {"MIT", "MIT License"},
	"https://opensource.org/license/mit":                  {"MIT", "MIT License"},
	"https://opensource.org/licenses/mit":                 {"MIT", "MIT License"},

	// CC0
	"http://creativecommons.org/publicdomain/zero/1.0":  {"CC0-1.0", "Creative Commons Zero v1.0 Universal"},
	"https://creativecommons.org/publicdomain/zero/1.0": {"CC0-1.0", "Creative Commons Zero v1.0 Universal"},

	// BSD
	"https://opensource.org/licenses/bsd-2-clause": {"BSD-2-Clause", "BSD 2-Clause \"Simplified\" License"},
	"https://opensource.org/licenses/bsd-3-clause": {"BSD-3-Clause", "BSD 3-Clause License"},

	// Eclipse
	"http://www.eclipse.org/legal/epl-2.0":                      {"EPL-2.0", "Eclipse Public License 2.0"},
	"https://www.eclipse.org/legal/epl-2.0":                     {"EPL-2.0", "Eclipse Public License 2.0"},
	"http://www.eclipse.org/org/documents/edl-v10.php":          {"BSD-3-Clause", "Eclipse Distribution License v1.0"},
	"https://projects.eclipse.org/license/epl-2.0":              {"EPL-2.0", "Eclipse Public License 2.0"},
	"https://www.eclipse.org/org/documents/epl-2.0/epl-2.0.txt": {"EPL-2.0", "Eclipse Public License 2.0"},

	// Classpath exception
	"https://projects.eclipse.org/license/secondary-gpl-2.0-cp": {"GPL-2.0-only WITH Classpath-exception-2.0", "GPL 2.0 with Classpath Exception"},
	"https://www.gnu.org/software/classpath/license.html":       {"GPL-2.0-only WITH Classpath-exception-2.0", "GPL 2.0 with Classpath Exception"},
	"http://www.gnu.org/software/classpath/license.html":        {"GPL-2.0-only WITH Classpath-exception-2.0", "GPL 2.0 with Classpath Exception"},
}

// NormalizeLicense maps a license ID/name pair to a canonical SPDX ID and
// display name. It applies a multi-step pipeline:
//  1. If SPDX ID is already set, pass through.
//  2. Extract quoted license name (e.g. "Apache 2.0";link="...").
//  3. Strip semicolon suffixes (e.g. BSD-3-Clause;link=...).
//  4. Try single-token normalization (URL map, then alias map).
//  5. Try compound expression parsing (split on "and"/"or"/",").
//  6. Fall through with no SPDX ID.
func NormalizeLicense(id, name string) (spdxID, displayName string) {
	if id != "" {
		displayName = name
		if displayName == "" {
			displayName = id
		}
		return id, displayName
	}

	cleaned := strings.TrimSpace(name)
	if cleaned == "" {
		return "", ""
	}

	// Extract quoted license name: "Apache 2.0";link="..." → Apache 2.0
	if strings.HasPrefix(cleaned, "\"") {
		if end := strings.Index(cleaned[1:], "\""); end > 0 {
			cleaned = cleaned[1 : 1+end]
		}
	}

	// Strip semicolon suffixes (e.g. BSD-3-Clause;link=https://...)
	if idx := strings.Index(cleaned, ";"); idx > 0 {
		cleaned = strings.TrimSpace(cleaned[:idx])
	}

	// Try single-token normalization.
	if spdx, display := normalizeSingle(cleaned); spdx != "" {
		return spdx, display
	}

	// Try compound expression (contains "and", "or", or ",").
	if expr, ok := normalizeExpression(cleaned); ok {
		return "", expr
	}

	// No match — return as-is with no SPDX ID.
	return "", name
}

// normalizeSingle tries to resolve a single (non-compound) license string.
func normalizeSingle(s string) (spdxID, displayName string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}

	// URL mapping.
	if strings.HasPrefix(strings.ToLower(s), "http") {
		key := strings.ToLower(strings.TrimRight(s, "/"))
		if mapped, ok := licenseURLs[key]; ok {
			return mapped.spdxID, mapped.name
		}
		return "", s
	}

	// Alias map.
	key := strings.ToLower(s)
	if alias, ok := licenseAlias[key]; ok {
		return alias.spdxID, alias.name
	}

	return "", s
}

// Expression separators in precedence order. " and " binds tighter than " or "
// in SPDX expressions, so we split on " and " first.
var exprSeps = []struct {
	pattern string // lowercase pattern
	spdxOp  string // SPDX operator for re-joining
}{
	{" and ", " AND "},
	{" or ", " OR "},
}

// normalizeExpression splits a compound license string on "and"/"or"/","
// separators, normalizes each part, and rejoins as an SPDX expression.
// Returns ("", false) if the string doesn't look compound.
func normalizeExpression(s string) (string, bool) {
	lower := strings.ToLower(s)

	for _, sep := range exprSeps {
		if strings.Contains(lower, sep.pattern) {
			parts := splitCaseInsensitive(s, sep.pattern)
			results := normalizeParts(parts)
			if len(results) >= 2 {
				return strings.Join(results, sep.spdxOp), true
			}
		}
	}

	// Comma separator.
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		results := normalizeParts(parts)
		if len(results) >= 2 {
			return strings.Join(results, " AND "), true
		}
	}

	return "", false
}

// normalizeParts normalizes each part of a compound expression.
func normalizeParts(parts []string) []string {
	var results []string
	for _, p := range parts {
		r := normalizePart(p)
		if r != "" {
			results = append(results, r)
		}
	}
	return results
}

// normalizePart normalizes a single part within a compound expression,
// handling parenthesized groups and "with exceptions" suffixes.
func normalizePart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Strip outer parentheses (preserving them in the output if present).
	hadParens := false
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = s[1 : len(s)-1]
		hadParens = true
	}

	// Strip RPM-style "with exceptions" suffix.
	lower := strings.ToLower(s)
	if idx := strings.Index(lower, " with exceptions"); idx > 0 {
		s = strings.TrimSpace(s[:idx])
	}

	// Try recursively as a sub-expression.
	if expr, ok := normalizeExpression(s); ok {
		if hadParens {
			return "(" + expr + ")"
		}
		return expr
	}

	// Try as single token.
	if spdx, _ := normalizeSingle(s); spdx != "" {
		return spdx
	}

	return s
}

// splitCaseInsensitive splits s on a case-insensitive separator.
func splitCaseInsensitive(s, sep string) []string {
	lower := strings.ToLower(s)
	lowerSep := strings.ToLower(sep)

	var parts []string
	for {
		idx := strings.Index(lower, lowerSep)
		if idx < 0 {
			parts = append(parts, s)
			break
		}
		parts = append(parts, s[:idx])
		s = s[idx+len(sep):]
		lower = lower[idx+len(lowerSep):]
	}
	return parts
}
