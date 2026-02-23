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

	pkghash "shai-hulud-scanner/pkg/hash"
	"shai-hulud-scanner/pkg/ioc"
	"shai-hulud-scanner/pkg/report"
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
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = nil

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
	if rpt.HasFindings() {
		t.Errorf("Run() on empty directory should not report findings, got: %+v", rpt.Findings)
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

func TestFeedCaching_FreshCSVCacheParsesPackageFieldAndSkipsHeader(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	cacheCSV := strings.Join([]string{
		"Package,Version",
		"@evil/scopepkg,= 1.2.3",
		"bad-unscoped,Some description",
		",,,",
		"",
	}, "\n")
	if err := os.WriteFile(cacheFile, []byte(cacheCSV), 0o644); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	// Create matching packages to verify scoped/unscoped tokens are parsed
	// from the first CSV field, not from whitespace-delimited text.
	scopedDir := filepath.Join(tmpDir, "node_modules", "@evil", "scopepkg")
	if err := os.MkdirAll(scopedDir, 0o755); err != nil {
		t.Fatalf("failed to create scoped package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scopedDir, "package.json"), []byte(`{"name":"@evil/scopepkg","version":"1.2.3"}`), 0o644); err != nil {
		t.Fatalf("failed to write scoped package.json: %v", err)
	}
	unscopedDir := filepath.Join(tmpDir, "node_modules", "bad-unscoped")
	if err := os.MkdirAll(unscopedDir, 0o755); err != nil {
		t.Fatalf("failed to create unscoped package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unscopedDir, "package.json"), []byte(`{"name":"bad-unscoped","version":"0.0.1"}`), 0o644); err != nil {
		t.Fatalf("failed to write unscoped package.json: %v", err)
	}

	// Should not be used because cache is fresh.
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

	if rpt.CompromisedPkgCount != 2 {
		t.Fatalf("CompromisedPkgCount = %d, want 2 (header and empty rows skipped)", rpt.CompromisedPkgCount)
	}

	findings := rpt.GetFindingsByType(report.FindingNodeModules)
	if len(findings) != 2 {
		t.Fatalf("node_modules findings = %d, want 2; output: %s", len(findings), buf.String())
	}

	foundScoped := false
	foundUnscoped := false
	for _, f := range findings {
		if f.Indicator == "@evil/scopepkg" {
			foundScoped = true
		}
		if f.Indicator == "bad-unscoped" {
			foundUnscoped = true
		}
		if f.Indicator == "Package" || strings.Contains(f.Indicator, ",Some") {
			t.Fatalf("unexpected malformed indicator parsed from CSV cache: %q", f.Indicator)
		}
	}
	if !foundScoped || !foundUnscoped {
		t.Fatalf("expected scoped and unscoped findings, got: %#v", findings)
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

func TestDetectsCompromisedNamespace(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer

	// Create a package.json with a dependency from a compromised namespace
	packageJSON := `{
  "name": "test-project",
  "dependencies": {
    "@crowdstrike/falcon-sensor": "^1.0.0",
    "lodash": "^4.17.21"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0o644); err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeQuick,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  false,
		CacheFile:  "",
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Check that the compromised namespace was detected
	found := false
	for _, f := range rpt.Findings {
		if strings.Contains(f.Indicator, "@crowdstrike") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find @crowdstrike namespace in findings, got findings: %+v", rpt.Findings)
	}
}

func TestDetectsCompromisedPackageInLockfile(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	// Setup a feed server with a known bad package
	feedHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "evil-package")
		fmt.Fprintln(w, "@evil/scoped-pkg")
	}
	server := httptest.NewServer(http.HandlerFunc(feedHandler))
	defer server.Close()

	ioc.PackageFeedURLs = []string{server.URL + "/feed.csv"}

	// Create a package-lock.json with the compromised package
	packageLock := `{
  "name": "test-project",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0"
    },
    "node_modules/evil-package": {
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(packageLock), 0o644); err != nil {
		t.Fatalf("Failed to create package-lock.json: %v", err)
	}

	var buf bytes.Buffer
	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeQuick,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  false,
		CacheFile:  cacheFile,
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Check that the compromised package in lockfile was detected
	found := false
	for _, f := range rpt.Findings {
		if strings.Contains(f.Indicator, "evil-package") && strings.Contains(string(f.Type), "lockfile") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find evil-package in lockfile findings, got findings: %+v", rpt.Findings)
	}
}

func TestDetectsScopedPackageInYarnLock(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	// Setup a feed server with a known bad scoped package
	feedHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "@evil/malicious-pkg")
	}
	server := httptest.NewServer(http.HandlerFunc(feedHandler))
	defer server.Close()

	ioc.PackageFeedURLs = []string{server.URL + "/feed.csv"}

	// Create a yarn.lock with the compromised scoped package
	yarnLock := `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@evil/malicious-pkg@^1.0.0":
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/@evil/malicious-pkg/-/malicious-pkg-1.0.0.tgz"
  integrity sha512-xxx

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-xxx
`
	if err := os.WriteFile(filepath.Join(tmpDir, "yarn.lock"), []byte(yarnLock), 0o644); err != nil {
		t.Fatalf("Failed to create yarn.lock: %v", err)
	}

	var buf bytes.Buffer
	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeQuick,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  false,
		CacheFile:  cacheFile,
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Check that the compromised scoped package in yarn.lock was detected
	found := false
	for _, f := range rpt.Findings {
		if strings.Contains(f.Indicator, "@evil/malicious-pkg") && strings.Contains(string(f.Type), "lockfile") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find @evil/malicious-pkg in yarn.lock findings, got findings: %+v", rpt.Findings)
	}
}

func TestDetectsPackageInPnpmLock(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")

	// Setup a feed server with a known bad package
	feedHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "bad-pnpm-pkg")
	}
	server := httptest.NewServer(http.HandlerFunc(feedHandler))
	defer server.Close()

	ioc.PackageFeedURLs = []string{server.URL + "/feed.csv"}

	// Create a pnpm-lock.yaml with the compromised package
	pnpmLock := `lockfileVersion: '6.0'

packages:

  /bad-pnpm-pkg@1.0.0:
    resolution: {integrity: sha512-xxx}
    dev: false

  /lodash@4.17.21:
    resolution: {integrity: sha512-xxx}
    dev: false
`
	if err := os.WriteFile(filepath.Join(tmpDir, "pnpm-lock.yaml"), []byte(pnpmLock), 0o644); err != nil {
		t.Fatalf("Failed to create pnpm-lock.yaml: %v", err)
	}

	var buf bytes.Buffer
	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeQuick,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  false,
		CacheFile:  cacheFile,
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Check that the compromised package in pnpm-lock.yaml was detected
	found := false
	for _, f := range rpt.Findings {
		if strings.Contains(f.Indicator, "bad-pnpm-pkg") && strings.Contains(string(f.Type), "lockfile") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find bad-pnpm-pkg in pnpm-lock.yaml findings, got findings: %+v", rpt.Findings)
	}
}

func TestParallelScansCompleteWithoutRace(t *testing.T) {
	// This test verifies that parallel scans don't cause data races
	// Run with -race flag to detect race conditions
	tmpDir := t.TempDir()

	// Create various files to trigger multiple scan paths
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{
		"name": "test",
		"dependencies": {"@crowdstrike/test": "1.0.0"}
	}`), 0o644)
	os.WriteFile(filepath.Join(tmpDir, "test.js"), []byte("process.env.AWS_ACCESS_KEY"), 0o644)
	os.MkdirAll(filepath.Join(tmpDir, ".github", "workflows"), 0o755)
	os.WriteFile(filepath.Join(tmpDir, ".github", "workflows", "ci.yml"), []byte("runs-on: ubuntu-latest"), 0o644)

	var buf bytes.Buffer
	cfg := &scanner.Config{
		RootPaths:  []string{tmpDir},
		ScanMode:   scanner.ScanModeFull,
		ReportPath: filepath.Join(tmpDir, "report.txt"),
		NoBanner:   true,
		FilesOnly:  false,
		CacheFile:  "",
		Output:     &buf,
	}

	s := scanner.New(cfg)
	rpt, err := s.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Just verify scan completed without panics or deadlocks
	if rpt == nil {
		t.Fatal("Run() returned nil report")
	}
}

func TestNodeModulesVersionConstraints_RespectPackageVersion(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = []string{"https://example.invalid/feed.csv"}

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")
	cacheCSV := "Package,Version\nversioned-pkg,= 1.2.3\n"
	if err := os.WriteFile(cacheFile, []byte(cacheCSV), 0o644); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	pkgDir := filepath.Join(tmpDir, "node_modules", "versioned-pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("failed to create package dir: %v", err)
	}
	writePkgJSON := func(version string) {
		t.Helper()
		content := fmt.Sprintf(`{"name":"versioned-pkg","version":"%s"}`, version)
		if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write package.json: %v", err)
		}
	}

	run := func() *report.Report {
		t.Helper()
		var buf bytes.Buffer
		cfg := scanner.DefaultConfig()
		cfg.RootPaths = []string{tmpDir}
		cfg.ScanMode = scanner.ScanModeQuick
		cfg.NoBanner = true
		cfg.FilesOnly = true
		cfg.CacheFile = cacheFile
		cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
		cfg.Output = &buf
		s := scanner.New(cfg)
		rpt, err := s.Run()
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		return rpt
	}

	writePkgJSON("9.9.9")
	rpt := run()
	if got := len(rpt.GetFindingsByType(report.FindingNodeModules)); got != 0 {
		t.Fatalf("non-matching version should not be flagged, got %d findings: %+v", got, rpt.Findings)
	}

	writePkgJSON("1.2.3")
	rpt = run()
	if got := len(rpt.GetFindingsByType(report.FindingNodeModules)); got != 1 {
		t.Fatalf("matching version should be flagged once, got %d findings: %+v", got, rpt.Findings)
	}
}

func TestPackageLockV3NestedPathDetectionAndVersionMatch(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = []string{"https://example.invalid/feed.csv"}

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")
	cacheCSV := "Package,Version\n@evil/nested-pkg,= 1.2.3\n"
	if err := os.WriteFile(cacheFile, []byte(cacheCSV), 0o644); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	lockfile := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/parent": {"version": "1.0.0"},
    "node_modules/parent/node_modules/@evil/nested-pkg": {"version": "1.2.3"}
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.NoBanner = true
	cfg.FilesOnly = false
	cfg.CacheFile = cacheFile
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.Output = &buf

	rpt, err := scanner.New(cfg).Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := false
	for _, f := range rpt.GetFindingsByType(report.FindingLockfileCompromised) {
		if strings.Contains(f.Indicator, "@evil/nested-pkg") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nested npm v7 package-lock package to be detected, findings: %+v", rpt.Findings)
	}
}

func TestPackageLockLegacyNestedDependenciesAreScanned(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = []string{"https://example.invalid/feed.csv"}

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")
	cacheCSV := "Package,Version\nlegacy-bad,= 2.3.4\n"
	if err := os.WriteFile(cacheFile, []byte(cacheCSV), 0o644); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	lockfile := `{
  "lockfileVersion": 1,
  "dependencies": {
    "parent": {
      "version": "1.0.0",
      "dependencies": {
        "legacy-bad": {
          "version": "2.3.4"
        }
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.NoBanner = true
	cfg.FilesOnly = false
	cfg.CacheFile = cacheFile
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.Output = &buf

	rpt, err := scanner.New(cfg).Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := false
	for _, f := range rpt.GetFindingsByType(report.FindingLockfileCompromised) {
		if strings.Contains(f.Indicator, "legacy-bad") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nested npm v6 dependency to be detected, findings: %+v", rpt.Findings)
	}
}

func TestLockfileVersionConstraints_DoNotFlagNonMatchingVersion(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = []string{"https://example.invalid/feed.csv"}

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")
	cacheCSV := "Package,Version\nversioned-bad,= 1.2.3\n"
	if err := os.WriteFile(cacheFile, []byte(cacheCSV), 0o644); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	lockfile := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/versioned-bad": {"version": "9.9.9"}
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.NoBanner = true
	cfg.FilesOnly = false
	cfg.CacheFile = cacheFile
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.Output = &buf

	rpt, err := scanner.New(cfg).Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	for _, f := range rpt.GetFindingsByType(report.FindingLockfileCompromised) {
		if strings.Contains(f.Indicator, "versioned-bad") {
			t.Fatalf("non-matching version should not be flagged, findings: %+v", rpt.Findings)
		}
	}
}

func TestYarnLockVersionConstraints_UseResolvedVersionLine(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = []string{"https://example.invalid/feed.csv"}

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "compromised-cache.txt")
	cacheCSV := strings.Join([]string{
		"Package,Version",
		"yarn-good,= 1.2.3",
		"yarn-bad,= 2.0.0",
	}, "\n")
	if err := os.WriteFile(cacheFile, []byte(cacheCSV), 0o644); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(cacheFile, now, now); err != nil {
		t.Fatalf("failed to set cache mtime: %v", err)
	}

	yarnLock := `# yarn lockfile v1
"yarn-good@^1.0.0", "yarn-good@~1.2.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/yarn-good/-/yarn-good-1.2.3.tgz"

"yarn-bad@^1.0.0":
  version "9.9.9"
  resolved "https://registry.yarnpkg.com/yarn-bad/-/yarn-bad-9.9.9.tgz"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "yarn.lock"), []byte(yarnLock), 0o644); err != nil {
		t.Fatalf("failed to write yarn.lock: %v", err)
	}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.NoBanner = true
	cfg.FilesOnly = false
	cfg.CacheFile = cacheFile
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.Output = &buf

	rpt, err := scanner.New(cfg).Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	lockFindings := rpt.GetFindingsByType(report.FindingLockfileCompromised)
	foundGood := false
	foundBad := false
	for _, f := range lockFindings {
		if strings.Contains(f.Indicator, "yarn-good") {
			foundGood = true
		}
		if strings.Contains(f.Indicator, "yarn-bad") {
			foundBad = true
		}
	}
	if !foundGood {
		t.Fatalf("expected yarn-good to be detected using resolved version line, findings: %+v", lockFindings)
	}
	if foundBad {
		t.Fatalf("did not expect yarn-bad to be detected (resolved version mismatch), findings: %+v", lockFindings)
	}
}

func TestFullModeHashScan_IncludesNodeModules(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = nil

	content := []byte("unit-test-malware-payload")
	sha, err := pkghash.ComputeSHA256FromReader(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("failed to hash test payload: %v", err)
	}
	origDesc, existed := ioc.MaliciousSHA256[sha]
	ioc.MaliciousSHA256[sha] = "test payload"
	defer func() {
		if existed {
			ioc.MaliciousSHA256[sha] = origDesc
		} else {
			delete(ioc.MaliciousSHA256, sha)
		}
	}()

	tmpDir := t.TempDir()
	jsPath := filepath.Join(tmpDir, "node_modules", "dep", "payload.js")
	if err := os.MkdirAll(filepath.Dir(jsPath), 0o755); err != nil {
		t.Fatalf("failed to create dirs: %v", err)
	}
	if err := os.WriteFile(jsPath, content, 0o644); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeFull
	cfg.NoBanner = true
	cfg.FilesOnly = false
	cfg.CacheFile = ""
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.Output = &buf

	rpt, err := scanner.New(cfg).Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	found := false
	for _, f := range rpt.GetFindingsByType(report.FindingMalwareHash) {
		if f.Location == jsPath {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected hash detection inside node_modules in full mode, findings: %+v", rpt.Findings)
	}
}

func TestQuickModeEnvCredentialFinding_NotDuplicated(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()
	ioc.PackageFeedURLs = nil

	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("TOKEN=test\n"), 0o644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	var buf bytes.Buffer
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = []string{tmpDir}
	cfg.ScanMode = scanner.ScanModeQuick
	cfg.NoBanner = true
	cfg.FilesOnly = false
	cfg.CacheFile = ""
	cfg.ReportPath = filepath.Join(tmpDir, "report.txt")
	cfg.Output = &buf

	rpt, err := scanner.New(cfg).Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	count := 0
	for _, f := range rpt.GetFindingsByType(report.FindingCredentialFile) {
		if f.Location == envPath {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one credential-file finding for root .env, got %d; findings: %+v", count, rpt.Findings)
	}
}
