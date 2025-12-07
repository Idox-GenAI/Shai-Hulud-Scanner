package scanner_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shai-hulud-scanner/pkg/ioc"
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
	if cfg.CacheFile == "" {
		t.Error("DefaultConfig() CacheFile should not be empty")
	}
	if filepath.Dir(cfg.CacheFile) != os.TempDir() {
		t.Errorf("DefaultConfig() CacheFile dir = %v, want %v", filepath.Dir(cfg.CacheFile), os.TempDir())
	}
	if !strings.HasSuffix(cfg.CacheFile, "compromised-packages-cache.txt") {
		t.Errorf("DefaultConfig() CacheFile name = %v, want compromised-packages-cache.txt", cfg.CacheFile)
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

func TestFeedCaching_SaveAndLoadFromCache(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	// Local HTTP server that serves a small feed of compromised packages.
	feedHandler := func(w http.ResponseWriter, r *http.Request) {
		// Mix of scoped and unscoped packages with extra CSV-like fields.
		fmt.Fprintln(w, "@evil/scopepkg,Some description")
		fmt.Fprintln(w, "bad-unscoped,Another field")
	}
	server := httptest.NewServer(http.HandlerFunc(feedHandler))
	defer server.Close()

	ioc.PackageFeedURLs = []string{server.URL + "/feed.csv"}

	// First run: fetch from feed and write to cache file.
	var buf1 bytes.Buffer
	cfg1 := scanner.DefaultConfig()
	cfg1.RootPaths = []string{tmpDir}
	cfg1.ScanMode = scanner.ScanModeQuick
	cfg1.ReportPath = filepath.Join(tmpDir, "report1.txt")
	cfg1.NoBanner = true
	cfg1.FilesOnly = true
	cfg1.CacheFile = cacheFile
	cfg1.Output = &buf1

	s1 := scanner.New(cfg1)
	rpt1, err := s1.Run()
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}

	if rpt1.CompromisedPkgCount != 2 {
		t.Fatalf("first run CompromisedPkgCount = %d, want 2", rpt1.CompromisedPkgCount)
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("failed to read cache file after first run: %v", err)
	}
	if !bytes.Contains(data, []byte("bad-unscoped")) {
		t.Fatalf("cache file does not contain expected package token; content: %s", string(data))
	}

	// Second run: simulate feed unavailability and ensure cache is used.
	ioc.PackageFeedURLs = []string{}

	var buf2 bytes.Buffer
	cfg2 := scanner.DefaultConfig()
	cfg2.RootPaths = []string{tmpDir}
	cfg2.ScanMode = scanner.ScanModeQuick
	cfg2.ReportPath = filepath.Join(tmpDir, "report2.txt")
	cfg2.NoBanner = true
	cfg2.FilesOnly = true
	cfg2.CacheFile = cacheFile
	cfg2.Output = &buf2

	s2 := scanner.New(cfg2)
	rpt2, err := s2.Run()
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}

	if rpt2.CompromisedPkgCount != 2 {
		t.Fatalf("second run CompromisedPkgCount = %d, want 2 (loaded from cache)", rpt2.CompromisedPkgCount)
	}

	output2 := buf2.String()
	if !strings.Contains(output2, "Using cached compromised package snapshot") {
		t.Fatalf("expected second run output to mention cache usage, got: %s", output2)
	}
}

func TestFeedCaching_UsesFreshCacheWhenRecent(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	// Create a cache file with a single package token and ensure it is "fresh".
	if err := os.WriteFile(cacheFile, []byte("fresh-pkg\n"), 0o644); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	// Use a bogus feed URL that must not be fetched when cache is fresh.
	ioc.PackageFeedURLs = []string{"https://example.invalid/feed.csv"}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.NoBanner = true
	cfg.FilesOnly = true
	cfg.CacheFile = cacheFile
	cfg.Output = &buf

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rpt.CompromisedPkgCount != 1 {
		t.Fatalf("CompromisedPkgCount = %d, want 1 (from fresh cache)", rpt.CompromisedPkgCount)
	}

	output := buf.String()
	if !strings.Contains(output, "Using cached compromised package snapshot (fresh, <24h)") {
		t.Fatalf("expected output to mention fresh cache usage, got: %s", output)
	}
	if strings.Contains(output, "Fetching compromised package list from:") {
		t.Fatalf("did not expect feeds to be fetched when cache is fresh, got: %s", output)
	}
}

func TestFeedCaching_UsesFeedWhenCacheStale(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	// Create a stale cache file with different content than the upcoming feed.
	if err := os.WriteFile(cacheFile, []byte("stale-pkg\n"), 0o644); err != nil {
		t.Fatalf("failed to write stale cache file: %v", err)
	}
	staleTime := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(cacheFile, staleTime, staleTime); err != nil {
		t.Fatalf("failed to set stale cache mtime: %v", err)
	}

	// HTTP server that serves a newer feed; this should be preferred over the stale cache.
	feedHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "new-pkg-one")
		fmt.Fprintln(w, "new-pkg-two")
	}
	server := httptest.NewServer(http.HandlerFunc(feedHandler))
	defer server.Close()

	ioc.PackageFeedURLs = []string{server.URL + "/feed.csv"}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.NoBanner = true
	cfg.FilesOnly = true
	cfg.CacheFile = cacheFile
	cfg.Output = &buf

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rpt.CompromisedPkgCount != 2 {
		t.Fatalf("CompromisedPkgCount = %d, want 2 (from refreshed feed)", rpt.CompromisedPkgCount)
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("failed to read cache file after run: %v", err)
	}
	if !bytes.Contains(data, []byte("new-pkg-one")) || bytes.Contains(data, []byte("stale-pkg")) {
		t.Fatalf("cache file not refreshed as expected; content: %s", string(data))
	}

	output := buf.String()
	if !strings.Contains(output, "Cache file is stale") {
		t.Fatalf("expected output to mention stale cache, got: %s", output)
	}
	if !strings.Contains(output, "Fetching compromised package list from:") {
		t.Fatalf("expected feeds to be fetched when cache is stale, got: %s", output)
	}
}
