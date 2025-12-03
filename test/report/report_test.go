package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shai-hulud-scanner/pkg/report"
)

func TestNewReport(t *testing.T) {
	paths := []string{"/home/user", "/projects"}
	r := report.NewReport("quick", paths)

	if r == nil {
		t.Fatal("NewReport() returned nil")
	}
	if r.ScanMode != "quick" {
		t.Errorf("NewReport() ScanMode = %v, want %v", r.ScanMode, "quick")
	}
	if len(r.PathsScanned) != 2 {
		t.Errorf("NewReport() PathsScanned length = %v, want %v", len(r.PathsScanned), 2)
	}
	if r.Timestamp.IsZero() {
		t.Error("NewReport() Timestamp should not be zero")
	}
	if len(r.Findings) != 0 {
		t.Errorf("NewReport() Findings should be empty, got %d", len(r.Findings))
	}
}

func TestAddFinding(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})

	r.AddFinding(report.FindingNodeModules, "evil-package", "/home/project/node_modules/evil-package")
	r.AddFinding(report.FindingMalwareHash, "SHA256 match: test", "/home/project/malware.js")

	if len(r.Findings) != 2 {
		t.Errorf("AddFinding() Findings count = %v, want %v", len(r.Findings), 2)
	}
	if r.Findings[0].Type != report.FindingNodeModules {
		t.Errorf("Finding[0].Type = %v, want %v", r.Findings[0].Type, report.FindingNodeModules)
	}
	if r.Findings[0].Indicator != "evil-package" {
		t.Errorf("Finding[0].Indicator = %v, want %v", r.Findings[0].Indicator, "evil-package")
	}
	if r.Findings[1].Type != report.FindingMalwareHash {
		t.Errorf("Finding[1].Type = %v, want %v", r.Findings[1].Type, report.FindingMalwareHash)
	}
}

func TestHasFindings(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})

	if r.HasFindings() {
		t.Error("HasFindings() should return false for empty report")
	}

	r.AddFinding(report.FindingFileArtefact, "shai-hulud.js", "/path/to/file")

	if !r.HasFindings() {
		t.Error("HasFindings() should return true after adding finding")
	}
}

func TestFindingCount(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})

	if r.FindingCount() != 0 {
		t.Errorf("FindingCount() = %v, want 0", r.FindingCount())
	}

	r.AddFinding(report.FindingFileArtefact, "file1", "/path1")
	r.AddFinding(report.FindingFileArtefact, "file2", "/path2")
	r.AddFinding(report.FindingGitBranch, "branch", "/repo")

	if r.FindingCount() != 3 {
		t.Errorf("FindingCount() = %v, want 3", r.FindingCount())
	}
}

func TestSetDuration(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})
	duration := 5 * time.Second

	r.SetDuration(duration)

	if r.Duration != duration {
		t.Errorf("SetDuration() Duration = %v, want %v", r.Duration, duration)
	}
}

func TestSetCompromisedPackageCount(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})

	r.SetCompromisedPackageCount(42)

	if r.CompromisedPkgCount != 42 {
		t.Errorf("SetCompromisedPackageCount() = %v, want 42", r.CompromisedPkgCount)
	}
}

func TestIsCritical(t *testing.T) {
	tests := []struct {
		name        string
		findingType report.FindingType
		wantCrit    bool
	}{
		{"malware hash is critical", report.FindingMalwareHash, true},
		{"malicious runner is critical", report.FindingMaliciousRunner, true},
		{"file artefact is not critical", report.FindingFileArtefact, false},
		{"node modules is not critical", report.FindingNodeModules, false},
		{"git branch is not critical", report.FindingGitBranch, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := report.NewReport("quick", []string{"/home"})
			r.AddFinding(tt.findingType, "test", "/path")
			if got := r.IsCritical(); got != tt.wantCrit {
				t.Errorf("IsCritical() = %v, want %v", got, tt.wantCrit)
			}
		})
	}
}

func TestGetFindingsByType(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})

	r.AddFinding(report.FindingNodeModules, "pkg1", "/path1")
	r.AddFinding(report.FindingFileArtefact, "file1", "/path2")
	r.AddFinding(report.FindingNodeModules, "pkg2", "/path3")
	r.AddFinding(report.FindingGitBranch, "branch1", "/path4")

	nodeFindings := r.GetFindingsByType(report.FindingNodeModules)
	if len(nodeFindings) != 2 {
		t.Errorf("GetFindingsByType(NodeModules) count = %v, want 2", len(nodeFindings))
	}

	fileFindings := r.GetFindingsByType(report.FindingFileArtefact)
	if len(fileFindings) != 1 {
		t.Errorf("GetFindingsByType(FileArtefact) count = %v, want 1", len(fileFindings))
	}

	emptyFindings := r.GetFindingsByType(report.FindingMalwareHash)
	if len(emptyFindings) != 0 {
		t.Errorf("GetFindingsByType(MalwareHash) count = %v, want 0", len(emptyFindings))
	}
}

func TestWrite(t *testing.T) {
	r := report.NewReport("quick", []string{"/home/user"})
	r.SetDuration(10 * time.Second)
	r.SetCompromisedPackageCount(100)
	r.AddFinding(report.FindingNodeModules, "evil-pkg", "/home/user/node_modules/evil-pkg")

	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()

	expectedStrings := []string{
		"Shai-Hulud Dynamic Detection Report",
		"Scan Mode: QUICK",
		"Paths Scanned: /home/user",
		"Compromised packages loaded: 100",
		"Indicators of compromise detected: 1",
		"node_modules",
		"evil-pkg",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Write() output missing expected string: %q", expected)
		}
	}
}

func TestWrite_NoFindings(t *testing.T) {
	r := report.NewReport("full", []string{"/home"})
	r.SetDuration(5 * time.Second)

	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No indicators of compromise found") {
		t.Error("Write() should contain 'No indicators of compromise found' when no findings")
	}
}

func TestWriteToFile(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})
	r.SetDuration(3 * time.Second)
	r.AddFinding(report.FindingFileArtefact, "shai-hulud.js", "/path/to/file")

	tmpDir := t.TempDir()
	reportFile := filepath.Join(tmpDir, "test-report.txt")

	if err := r.WriteToFile(reportFile); err != nil {
		t.Fatalf("WriteToFile() error = %v", err)
	}

	content, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}
	if len(content) == 0 {
		t.Error("WriteToFile() created empty file")
	}
	if !strings.Contains(string(content), "Shai-Hulud") {
		t.Error("WriteToFile() content missing expected header")
	}
}

func TestWriteToFile_InvalidPath(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})

	if err := r.WriteToFile("/nonexistent/directory/report.txt"); err == nil {
		t.Error("WriteToFile() should return error for invalid path")
	}
}

func TestPrintSummary(t *testing.T) {
	r := report.NewReport("quick", []string{"/home"})
	r.SetDuration(5 * time.Second)
	r.AddFinding(report.FindingMalwareHash, "SHA256 match: malware", "/path/to/malware.js")

	var buf bytes.Buffer
	r.PrintSummary(&buf)
	output := buf.String()

	expectedStrings := []string{
		"Summary",
		"Scan completed",
		"QUICK",
		"POTENTIAL INDICATORS OF COMPROMISE FOUND: 1",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("PrintSummary() output missing expected string: %q", expected)
		}
	}
}

func TestPrintSummary_NoFindings(t *testing.T) {
	r := report.NewReport("full", []string{"/home"})
	r.SetDuration(10 * time.Second)

	var buf bytes.Buffer
	r.PrintSummary(&buf)
	output := buf.String()
	if !strings.Contains(output, "No indicators of Shai-Hulud compromise") {
		t.Error("PrintSummary() should indicate no findings when clean")
	}
}

func TestFindingString(t *testing.T) {
	f := report.Finding{
		Type:      report.FindingMalwareHash,
		Indicator: "SHA256 match: test malware",
		Location:  "/home/user/malware.js",
	}

	str := f.String()

	if !strings.Contains(str, "malware-hash") {
		t.Error("Finding.String() should contain finding type")
	}
	if !strings.Contains(str, "SHA256 match") {
		t.Error("Finding.String() should contain indicator")
	}
	if !strings.Contains(str, "/home/user/malware.js") {
		t.Error("Finding.String() should contain location")
	}
}

func TestFindingTypes(t *testing.T) {
	types := []report.FindingType{
		report.FindingNodeModules,
		report.FindingNpmCache,
		report.FindingFileArtefact,
		report.FindingGitBranch,
		report.FindingGitRemote,
		report.FindingWorkflowPattern,
		report.FindingWorkflowContent,
		report.FindingCredentialFile,
		report.FindingMaliciousRunner,
		report.FindingRunnerInstallation,
		report.FindingPostinstallHook,
		report.FindingMalwareHash,
		report.FindingMigrationAttack,
		report.FindingTrufflehog,
		report.FindingTrufflehogRef,
		report.FindingEnvExfil,
	}

	for _, ft := range types {
		if string(ft) == "" {
			t.Errorf("FindingType %v has empty string representation", ft)
		}
	}
}
