package service

import (
	"testing"

	"github.com/matryer/is"
)

func TestNormalizeLicense(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		inputName   string
		wantSpdxID  string
		wantDisplay string
	}{
		// Passthrough
		{"spdx id passthrough", "MIT", "", "MIT", "MIT"},
		{"spdx id with name", "MIT", "MIT License", "MIT", "MIT License"},

		// Simple aliases
		{"mit bare", "", "MIT", "MIT", "MIT License"},
		{"mit alias", "", "MIT License", "MIT", "MIT License"},
		{"mit alias case insensitive", "", "mit license", "MIT", "MIT License"},
		{"gplv2+", "", "GPLv2+", "GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
		{"gpl bare", "", "GPL", "GPL-2.0-or-later", "GNU General Public License v2.0 or later"},
		{"apache 2.0", "", "Apache 2.0", "Apache-2.0", "Apache License 2.0"},
		{"asl 2.0", "", "ASL 2.0", "Apache-2.0", "Apache License 2.0"},
		{"bsd bare", "", "BSD", "BSD-3-Clause", "BSD 3-Clause License"},
		{"public-domain", "", "public-domain", "Unlicense", "The Unlicense"},
		{"public domain spaces", "", "  Public Domain  ", "Unlicense", "The Unlicense"},
		{"lgpl bare", "", "LGPL", "LGPL-2.1-or-later", "GNU Lesser General Public License v2.1 or later"},
		{"mpl", "", "MPL", "MPL-2.0", "Mozilla Public License 2.0"},
		{"boost", "", "Boost", "BSL-1.0", "Boost Software License 1.0"},
		{"zlib", "", "zlib", "Zlib", "zlib License"},
		{"isc license", "", "ISC License", "ISC", "ISC License"},
		{"empty both", "", "", "", ""},

		// New aliases from real data
		{"lgplv2+", "", "LGPLv2+", "LGPL-2.0-or-later", "GNU Library General Public License v2 or later"},
		{"lgplv3+", "", "LGPLv3+", "LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later"},
		{"mplv2.0", "", "MPLv2.0", "MPL-2.0", "Mozilla Public License 2.0"},
		{"the unlicense", "", "The Unlicense", "Unlicense", "The Unlicense"},
		{"verbose apache", "", "Apache License, Version 2.0", "Apache-2.0", "Apache License 2.0"},
		{"the apache software license", "", "The Apache Software License, Version 2.0", "Apache-2.0", "Apache License 2.0"},
		{"apache license bare", "", "Apache License", "Apache-2.0", "Apache License 2.0"},
		{"eclipse public license", "", "Eclipse Public License - v 2.0", "EPL-2.0", "Eclipse Public License 2.0"},
		{"verbose gpl", "", "GNU General Public License v3.0 only", "GPL-3.0-only", "GNU General Public License v3.0 only"},
		{"bsd with advertising", "", "BSD with advertising", "BSD-4-Clause", "BSD 4-Clause \"Original\" License"},
		{"isc bare", "", "ISC", "ISC", "ISC License"},
		{"gfdl", "", "GFDL", "GFDL-1.3-or-later", "GNU Free Documentation License v1.3 or later"},

		// Known SPDX IDs arriving as names
		{"ssh-openssh", "", "SSH-OpenSSH", "SSH-OpenSSH", "SSH OpenSSH License"},
		{"x11", "", "X11", "X11", "X11 License"},
		{"openssl", "", "OpenSSL", "OpenSSL", "OpenSSL License"},
		{"blessing", "", "blessing", "blessing", "SQLite Blessing"},
		{"curl", "", "curl", "curl", "curl License"},
		{"oldap-2.8", "", "OLDAP-2.8", "OLDAP-2.8", "Open LDAP Public License v2.8"},

		// Semicolon stripping
		{"semicolon suffix", "", "BSD-3-Clause;link=https://asm.ow2.io/LICENSE.txt", "BSD-3-Clause", "BSD 3-Clause License"},

		// URL mapping
		{"apache url txt", "", "http://www.apache.org/licenses/LICENSE-2.0.txt", "Apache-2.0", "Apache License 2.0"},
		{"apache url html", "", "http://www.apache.org/licenses/LICENSE-2.0.html", "Apache-2.0", "Apache License 2.0"},
		{"jboss apache url", "", "http://repository.jboss.org/licenses/apache-2.0.txt", "Apache-2.0", "Apache License 2.0"},
		{"eclipse epl url", "", "http://www.eclipse.org/legal/epl-2.0", "EPL-2.0", "Eclipse Public License 2.0"},
		{"eclipse edl url", "", "http://www.eclipse.org/org/documents/edl-v10.php", "BSD-3-Clause", "Eclipse Distribution License v1.0"},
		{"unknown url passthrough", "", "http://example.com/unknown", "", "http://example.com/unknown"},

		// Compound expressions (and)
		{"and compound", "", "LGPLv2+ and GPLv3+", "", "LGPL-2.0-or-later AND GPL-3.0-or-later"},
		{"and compound three", "", "BSD and GPLv2 and ISC", "", "BSD-3-Clause AND GPL-2.0-only AND ISC"},
		{"and with unknown", "", "BSD and Inner-Net", "", "BSD-3-Clause AND Inner-Net"},

		// Compound expressions (or)
		{"or compound", "", "LGPLv3+ or GPLv2+", "", "LGPL-3.0-or-later OR GPL-2.0-or-later"},
		{"or compound bare", "", "BSD or GPLv2", "", "BSD-3-Clause OR GPL-2.0-only"},

		// Compound with parentheses
		{"parens or inside and", "", "(GPLv2+ or LGPLv3+) and GPLv3+", "", "(GPL-2.0-or-later OR LGPL-3.0-or-later) AND GPL-3.0-or-later"},
		{"parens flipped", "", "(LGPLv3+ or GPLv2+) and GPLv3+", "", "(LGPL-3.0-or-later OR GPL-2.0-or-later) AND GPL-3.0-or-later"},

		// Compound with "with exceptions"
		{"with exceptions stripped", "", "GPLv2+ with exceptions and BSD", "", "GPL-2.0-or-later AND BSD-3-Clause"},
		{"multiple with exceptions", "", "LGPLv2+ and LGPLv2+ with exceptions and GPLv2+ and GPLv2+ with exceptions and BSD and ISC and Public Domain and GFDL", "",
			"LGPL-2.0-or-later AND LGPL-2.0-or-later AND GPL-2.0-or-later AND GPL-2.0-or-later AND BSD-3-Clause AND ISC AND Unlicense AND GFDL-1.3-or-later"},

		// Comma-separated
		{"comma separated", "", "LGPLv2.1,GPLv2", "", "LGPL-2.1-only AND GPL-2.0-only"},

		// Comma-separated URLs
		{"comma urls", "", "http://www.eclipse.org/legal/epl-2.0, https://www.gnu.org/software/classpath/license.html", "",
			"EPL-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0"},

		// Unknown passthrough
		{"unknown passthrough", "", "Custom Corporate License", "", "Custom Corporate License"},
		{"custom", "", "Custom", "", "Custom"},
		{"pubkey", "", "pubkey", "", "pubkey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			spdxID, display := NormalizeLicense(tt.id, tt.inputName)
			is.Equal(spdxID, tt.wantSpdxID)
			is.Equal(display, tt.wantDisplay)
		})
	}
}

func TestSplitCaseInsensitive(t *testing.T) {
	is := is.New(t)

	is.Equal(splitCaseInsensitive("a and b", " and "), []string{"a", "b"})
	is.Equal(splitCaseInsensitive("a AND b", " and "), []string{"a", "b"})
	is.Equal(splitCaseInsensitive("a And B And C", " and "), []string{"a", "B", "C"})
	is.Equal(splitCaseInsensitive("no separator", " and "), []string{"no separator"})
}
