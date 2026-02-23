package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"shai-hulud-scanner/pkg/config"
	"shai-hulud-scanner/pkg/report"
)

func TestLoadAllowlist(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	content := `{
		"allowPackages": ["core-js", "@cypress/*"],
		"allowPaths": ["**/node_modules/cypress/**"],
		"disableFindingTypes": ["credential-file", "postinstall-hook"]
	}`

	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	allowlist, err := config.LoadAllowlist(configFile)
	if err != nil {
		t.Fatalf("LoadAllowlist() error = %v", err)
	}

	if allowlist == nil {
		t.Fatal("LoadAllowlist() returned nil")
	}

	if len(allowlist.AllowPackages) != 2 {
		t.Errorf("AllowPackages length = %d, want 2", len(allowlist.AllowPackages))
	}
	if len(allowlist.AllowPaths) != 1 {
		t.Errorf("AllowPaths length = %d, want 1", len(allowlist.AllowPaths))
	}
	if len(allowlist.DisableFindingTypes) != 2 {
		t.Errorf("DisableFindingTypes length = %d, want 2", len(allowlist.DisableFindingTypes))
	}
}

func TestLoadAllowlist_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.json")

	content := `{ invalid json }`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := config.LoadAllowlist(configFile)
	if err == nil {
		t.Error("LoadAllowlist() should return error for invalid JSON")
	}
}

func TestLoadAllowlist_FileNotFound(t *testing.T) {
	_, err := config.LoadAllowlist("/nonexistent/path/config.json")
	if err == nil {
		t.Error("LoadAllowlist() should return error for nonexistent file")
	}
}

func TestLoadAllowlist_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "empty.json")

	content := `{}`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	allowlist, err := config.LoadAllowlist(configFile)
	if err != nil {
		t.Fatalf("LoadAllowlist() error = %v", err)
	}

	if allowlist == nil {
		t.Fatal("LoadAllowlist() returned nil for empty config")
	}
}

func TestIsPackageAllowed_ExactMatch(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPackages: []string{"core-js", "lodash", "@babel/core"},
	}

	tests := []struct {
		pkgName string
		want    bool
	}{
		{"core-js", true},
		{"lodash", true},
		{"@babel/core", true},
		{"react", false},
		{"core-js-compat", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			if got := allowlist.IsPackageAllowed(tt.pkgName); got != tt.want {
				t.Errorf("IsPackageAllowed(%q) = %v, want %v", tt.pkgName, got, tt.want)
			}
		})
	}
}

func TestIsPackageAllowed_GlobPatterns(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPackages: []string{"@cypress/*", "@angular/*", "*-loader"},
	}

	tests := []struct {
		pkgName string
		want    bool
	}{
		{"@cypress/react", true},
		{"@cypress/vue", true},
		{"@angular/core", true},
		{"@angular/common", true},
		{"css-loader", true},
		{"babel-loader", true},
		{"@babel/core", false},  // Not matching @cypress/* or @angular/*
		{"cypress", false},      // Not scoped
		{"loader", false},       // Doesn't end with -loader
		{"loader-utils", false}, // Has -loader in middle, not end
	}

	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			if got := allowlist.IsPackageAllowed(tt.pkgName); got != tt.want {
				t.Errorf("IsPackageAllowed(%q) = %v, want %v", tt.pkgName, got, tt.want)
			}
		})
	}
}

func TestIsPackageAllowed_NilAllowlist(t *testing.T) {
	var allowlist *config.Allowlist = nil

	if allowlist.IsPackageAllowed("any-package") {
		t.Error("IsPackageAllowed() should return false for nil allowlist")
	}
}

func TestIsPathAllowed(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPaths: []string{
			"**/node_modules/cypress/**",
			"**/test/**",
			"**/vendor/**",
		},
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/project/node_modules/cypress/lib/runner.js", true},
		{"/project/node_modules/cypress/index.js", true},
		{"/home/user/project/test/unit/test.js", true},
		{"/project/vendor/lib.js", true},
		{"/project/src/main.js", false},
		{"/project/node_modules/lodash/index.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := allowlist.IsPathAllowed(tt.path); got != tt.want {
				t.Errorf("IsPathAllowed(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsPathAllowed_NilAllowlist(t *testing.T) {
	var allowlist *config.Allowlist = nil

	if allowlist.IsPathAllowed("/any/path") {
		t.Error("IsPathAllowed() should return false for nil allowlist")
	}
}

func TestIsFindingTypeDisabled(t *testing.T) {
	allowlist := &config.Allowlist{
		DisableFindingTypes: []string{"credential-file", "postinstall-hook", "ENV-EXFIL-PATTERN"},
	}

	tests := []struct {
		findingType report.FindingType
		want        bool
	}{
		{report.FindingCredentialFile, true},
		{report.FindingPostinstallHook, true},
		{report.FindingEnvExfil, true}, // Case insensitive match
		{report.FindingNodeModules, false},
		{report.FindingMalwareHash, false},
		{report.FindingGitBranch, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.findingType), func(t *testing.T) {
			if got := allowlist.IsFindingTypeDisabled(tt.findingType); got != tt.want {
				t.Errorf("IsFindingTypeDisabled(%q) = %v, want %v", tt.findingType, got, tt.want)
			}
		})
	}
}

func TestIsFindingTypeDisabled_NilAllowlist(t *testing.T) {
	var allowlist *config.Allowlist = nil

	if allowlist.IsFindingTypeDisabled(report.FindingCredentialFile) {
		t.Error("IsFindingTypeDisabled() should return false for nil allowlist")
	}
}

func TestShouldSkipFinding_DisabledType(t *testing.T) {
	allowlist := &config.Allowlist{
		DisableFindingTypes: []string{"credential-file"},
	}

	if !allowlist.ShouldSkipFinding(report.FindingCredentialFile, ".env", "/project/.env") {
		t.Error("ShouldSkipFinding() should return true for disabled finding type")
	}

	if allowlist.ShouldSkipFinding(report.FindingNodeModules, "bad-pkg", "/project/node_modules/bad-pkg") {
		t.Error("ShouldSkipFinding() should return false for non-disabled finding type")
	}
}

func TestShouldSkipFinding_AllowedPath(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPaths: []string{"**/test/**"},
	}

	if !allowlist.ShouldSkipFinding(report.FindingEnvExfil, "env pattern", "/project/test/helper.js") {
		t.Error("ShouldSkipFinding() should return true for allowed path")
	}

	if allowlist.ShouldSkipFinding(report.FindingEnvExfil, "env pattern", "/project/src/main.js") {
		t.Error("ShouldSkipFinding() should return false for non-allowed path")
	}
}

func TestShouldSkipFinding_AllowedPackage(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPackages: []string{"core-js", "@cypress/*"},
	}

	// Package findings should check allowPackages
	if !allowlist.ShouldSkipFinding(report.FindingNodeModules, "core-js", "/project/node_modules/core-js") {
		t.Error("ShouldSkipFinding() should return true for allowed package (node_modules)")
	}

	if !allowlist.ShouldSkipFinding(report.FindingNpmCache, "@cypress/react", "/cache/@cypress/react") {
		t.Error("ShouldSkipFinding() should return true for allowed scoped package (npm-cache)")
	}

	// Non-package findings should not check allowPackages
	if allowlist.ShouldSkipFinding(report.FindingCredentialFile, "core-js", "/project/.env") {
		t.Error("ShouldSkipFinding() should not check allowPackages for non-package findings")
	}
}

func TestShouldSkipFinding_NilAllowlist(t *testing.T) {
	var allowlist *config.Allowlist = nil

	if allowlist.ShouldSkipFinding(report.FindingNodeModules, "any", "/any/path") {
		t.Error("ShouldSkipFinding() should return false for nil allowlist")
	}
}

func TestShouldSkipFinding_CombinedRules(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPackages:       []string{"safe-pkg"},
		AllowPaths:          []string{"**/allowed/**"},
		DisableFindingTypes: []string{"credential-file"},
	}

	tests := []struct {
		name      string
		ft        report.FindingType
		indicator string
		location  string
		want      bool
	}{
		{"disabled type wins", report.FindingCredentialFile, ".env", "/project/src/.env", true},
		{"allowed path wins", report.FindingEnvExfil, "pattern", "/project/allowed/file.js", true},
		{"allowed package wins", report.FindingNodeModules, "safe-pkg", "/project/node_modules/safe-pkg", true},
		{"nothing matches", report.FindingNodeModules, "bad-pkg", "/project/node_modules/bad-pkg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowlist.ShouldSkipFinding(tt.ft, tt.indicator, tt.location); got != tt.want {
				t.Errorf("ShouldSkipFinding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPathAllowed_GlobWildcardsAndMultipleDoubleStars(t *testing.T) {
	allowlist := &config.Allowlist{
		AllowPaths: []string{
			"**/*.min.js",
			"**/node_modules/**/cypress/**",
			"**/vendor/*.js",
		},
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/project/dist/app.min.js", true},
		{"/project/dist/app.js", false},
		{"/project/node_modules/a/node_modules/cypress/lib/index.js", true},
		{"/project/vendor/util.js", true},
		{"/project/vendor/nested/util.js", false}, // single-segment * only
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := allowlist.IsPathAllowed(tt.path); got != tt.want {
				t.Errorf("IsPathAllowed(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
