package scanner_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shai-hulud-scanner/pkg/scanner"
)

func TestDefaultConfig(t *testing.T) {
	cfg := scanner.DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if len(cfg.RootPaths) != 1 {
		t.Errorf("DefaultConfig() RootPaths length = %v, want 1", len(cfg.RootPaths))
	}
	if cfg.ScanMode != scanner.ScanModeQuick {
		t.Errorf("DefaultConfig() ScanMode = %v, want %v", cfg.ScanMode, scanner.ScanModeQuick)
	}
	if cfg.ReportPath == "" {
		t.Error("DefaultConfig() ReportPath should not be empty")
	}
	if cfg.Output == nil {
		t.Error("DefaultConfig() Output should not be nil")
	}
}

func TestRunEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer

	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeQuick,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  true,
		CacheFile:  "",
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if rpt == nil {
		t.Fatal("Run() returned nil report")
	}
	output := buf.String()
	if strings.Contains(output, "[!]") {
		t.Errorf("Run() on empty directory should not report findings, output: %s", output)
	}
}

func TestRunDetectsMaliciousFile(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer

	maliciousFile := filepath.Join(tmpDir, "shai-hulud.js")
	if err := os.WriteFile(maliciousFile, []byte("malicious content"), 0o644); err != nil {
		t.Fatalf("Failed to create malicious file: %v", err)
	}

	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeQuick,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  true,
		CacheFile:  "",
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	_ = rpt

	output := buf.String()
	if !strings.Contains(output, "shai-hulud.js") {
		t.Fatalf("Expected output to mention malicious file shai-hulud.js, got: %s", output)
	}
}
