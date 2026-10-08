package scanner

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"shai-hulud-scanner/pkg/config"
	"shai-hulud-scanner/pkg/report"
)

func TestOpenAPIArtifactPaths(t *testing.T) {
	for _, mode := range []ScanMode{ScanModeQuick, ScanModeFull} {
		t.Run(string(mode), func(t *testing.T) {
			root := t.TempDir()
			paths := []string{
				".local/bin/sysvinit-detect-fash.sh",
				".config/sysvinit-detect-fash/fox",
				".config/sysvinit-detect-fash/fash-detected",
				".config/sysvinit-detect-fash/runit",
				"Library/LaunchAgents/com.user.sysvinit-detect-fash.plist",
				".config/systemd/user/sysvinit-detect-fash.service",
				"node_modules/@7nohe/openapi-react-query-codegen/nu.js",
			}
			for _, path := range paths {
				writeOpenAPIFixture(t, root, path, "inert artifact")
			}
			for _, path := range []string{"fox", "runit", "nu.js", "ai_init.js", "binding.gyp", "node_modules/legitimate/nu.js", ".config/legitimate/fox", ".config/index.js", ".github/_index.js"} {
				writeOpenAPIFixture(t, root, path, "benign fixture")
			}
			s := New(&Config{RootPaths: []string{root}, ScanMode: mode, Output: io.Discard})
			s.scanMaliciousFiles()
			findings := s.report.GetFindingsByType(report.FindingFileArtifact)
			if len(findings) != len(paths) {
				t.Fatalf("artifact findings = %+v, want %d", findings, len(paths))
			}
			for _, path := range paths {
				if !hasFindingLocation(findings, filepath.Join(root, filepath.FromSlash(path))) {
					t.Errorf("missing artifact %s", path)
				}
			}
			s = New(&Config{RootPaths: []string{root}, ScanMode: mode, Output: io.Discard, Allowlist: &config.Allowlist{DisableFindingTypes: []string{"file-artifact"}}})
			s.scanMaliciousFiles()
			if s.report.HasFindings() {
				t.Errorf("disabled artifact findings were reported: %+v", s.report.Findings)
			}
		})
	}
}

func TestOpenAPISecretDumpWorkflowSeverity(t *testing.T) {
	root := t.TempDir()
	path := writeOpenAPIFixture(t, root, ".github/workflows/review.yml", `name: ClaudeCode Review
on: [deployment]
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      DATA: ${{ toJSON(secrets) }}
    steps:
      - uses: actions/upload-artifact@inert-test-reference
        with:
          path: res.txt
`)
	s := New(&Config{RootPaths: []string{root}, Output: io.Discard})
	s.scanWorkflows()
	findings := s.report.GetFindingsByType(report.FindingWorkflowPattern)
	if len(findings) != 1 || findings[0].Severity != report.SeverityHigh || findings[0].Location != path {
		t.Fatalf("workflow findings = %+v, want one high-severity finding at %s", findings, path)
	}
}

func TestOpenAPILifecycleHookWarnings(t *testing.T) {
	root := t.TempDir()
	path := writeOpenAPIFixture(t, root, "package.json", `{"scripts":{"preinstall":"node 3FWCvzduYZg.js","install":"bun is_it_this_simple.js"}}`)
	s := New(&Config{RootPaths: []string{root}, Output: io.Discard})
	s.checkPackageJson(path)
	findings := s.report.GetFindingsByType(report.FindingPostinstallHook)
	if len(findings) != 2 {
		t.Fatalf("hook findings = %+v, want two", findings)
	}
	for _, finding := range findings {
		if finding.Severity != report.SeverityWarning {
			t.Errorf("hook severity = %s, want warning", finding.Severity)
		}
	}
}

func writeOpenAPIFixture(t *testing.T, root, relativePath, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
