package scanner

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pkghash "shai-hulud-scanner/pkg/hash"
	"shai-hulud-scanner/pkg/ioc"
	"shai-hulud-scanner/pkg/report"
)

func TestSaveCacheFileReturnsError(t *testing.T) {
	tmpDir := t.TempDir()

	// Force MkdirAll/create failure by making an intermediate path a file.
	blocker := filepath.Join(tmpDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	s := New(&Config{
		CacheFile: filepath.Join(blocker, "cache", "compromised.txt"),
	})

	if err := s.saveCacheFile([]string{"bad-pkg"}); err == nil {
		t.Fatal("saveCacheFile() returned nil error, want failure")
	}
}

func TestPathDirSegmentCount(t *testing.T) {
	tests := []struct {
		path    string
		segment string
		want    int
	}{
		{"/tmp/project/node_modules/pkg/file.js", "node_modules", 1},
		{"/tmp/project/node_modules/a/node_modules/b/package.json", "node_modules", 2},
		{"/tmp/project/my-node_modules-copy/package-lock.json", "node_modules", 0},
		{"node_modules", "node_modules", 1},
	}

	for _, tt := range tests {
		if got := pathDirSegmentCount(tt.path, tt.segment); got != tt.want {
			t.Fatalf("pathDirSegmentCount(%q, %q) = %d, want %d", tt.path, tt.segment, got, tt.want)
		}
	}
}

func TestIsCompromisedInstalledPackageSkipsVersionReadForAnyVersionIOC(t *testing.T) {
	s := New(&Config{})
	s.addCompromisedPackage("bad-pkg", nil)

	missingPkgDir := filepath.Join(t.TempDir(), "bad-pkg")
	if !s.isCompromisedInstalledPackage("bad-pkg", missingPkgDir) {
		t.Fatal("isCompromisedInstalledPackage() = false for version-agnostic IOC without package.json, want true")
	}
}

func TestIsCompromisedInstalledPackageReadsVersionForPinnedIOC(t *testing.T) {
	tmpDir := t.TempDir()
	pkgDir := filepath.Join(tmpDir, "bad-pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("failed to create package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"version":"1.2.3"}`), 0o644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	s := New(&Config{})
	s.addCompromisedPackage("bad-pkg", []string{"1.2.3"})

	if !s.isCompromisedInstalledPackage("bad-pkg", pkgDir) {
		t.Fatal("isCompromisedInstalledPackage() = false for matching pinned IOC, want true")
	}
}

func TestScanWorkflowsSkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()
	rootWorkflowDir := filepath.Join(tmpDir, ".github", "workflows")
	depWorkflowDir := filepath.Join(tmpDir, "node_modules", "dep", ".github", "workflows")
	if err := os.MkdirAll(rootWorkflowDir, 0o755); err != nil {
		t.Fatalf("failed to create root workflow dir: %v", err)
	}
	if err := os.MkdirAll(depWorkflowDir, 0o755); err != nil {
		t.Fatalf("failed to create dependency workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootWorkflowDir, "formatter_123.yml"), []byte("name: root\n"), 0o644); err != nil {
		t.Fatalf("failed to write root workflow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(depWorkflowDir, "formatter_456.yml"), []byte("name: dependency\n"), 0o644); err != nil {
		t.Fatalf("failed to write dependency workflow: %v", err)
	}

	var out bytes.Buffer
	s := New(&Config{
		RootPaths: []string{tmpDir},
		ScanMode:  ScanModeFull,
		Output:    &out,
	})
	s.scanWorkflows()

	findings := s.report.GetFindingsByType(report.FindingWorkflowPattern)
	if len(findings) != 1 {
		t.Fatalf("workflow pattern findings = %d, want 1: %+v", len(findings), findings)
	}
	wantLocation := filepath.Join(rootWorkflowDir, "formatter_123.yml")
	if findings[0].Location != wantLocation {
		t.Fatalf("workflow finding location = %q, want %q", findings[0].Location, wantLocation)
	}
}

func TestLoadCompromisedPackagesFetchesFeedsConcurrently(t *testing.T) {
	origURLs := append([]string(nil), ioc.PackageFeedURLs...)
	defer func() { ioc.PackageFeedURLs = origURLs }()

	var started atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if started.Add(1) == 2 {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(time.Second):
			http.Error(w, "feed request was not concurrent", http.StatusGatewayTimeout)
			return
		}

		switch r.URL.Path {
		case "/one":
			_, _ = w.Write([]byte("feed-one\n"))
		case "/two":
			_, _ = w.Write([]byte("feed-two\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ioc.PackageFeedURLs = []string{server.URL + "/one", server.URL + "/two"}

	var out bytes.Buffer
	s := New(&Config{
		CacheFile: filepath.Join(t.TempDir(), "cache.txt"),
		Output:    &out,
	})
	if err := s.loadCompromisedPackages(); err != nil {
		t.Fatalf("loadCompromisedPackages() error = %v", err)
	}
	if !s.compromisedPkgs["feed-one"] || !s.compromisedPkgs["feed-two"] {
		t.Fatalf("loaded compromised packages = %+v, want feed-one and feed-two", s.compromisedPkgs)
	}
}

func TestScanHashesFindsAllParallelCandidates(t *testing.T) {
	content := []byte("parallel-hash-test-payload")
	sha, err := pkghash.ComputeSHA256FromReader(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("failed to hash test payload: %v", err)
	}
	origDesc, existed := ioc.MaliciousSHA256[sha]
	ioc.MaliciousSHA256[sha] = "parallel test payload"
	defer func() {
		if existed {
			ioc.MaliciousSHA256[sha] = origDesc
		} else {
			delete(ioc.MaliciousSHA256, sha)
		}
	}()

	tmpDir := t.TempDir()
	for _, rel := range []string{
		"one.js",
		filepath.Join("nested", "two.ts"),
		filepath.Join("node_modules", "dep", "three.js"),
		filepath.Join("node_modules", "dep", "four.ts"),
	} {
		path := filepath.Join(tmpDir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", rel, err)
		}
	}

	var out bytes.Buffer
	s := New(&Config{
		RootPaths: []string{tmpDir},
		ScanMode:  ScanModeFull,
		Output:    &out,
	})
	s.scanHashes()

	findings := s.report.GetFindingsByType(report.FindingMalwareHash)
	if len(findings) != 4 {
		t.Fatalf("hash findings = %d, want 4: %+v", len(findings), findings)
	}
}

func TestScanTrufflehogIncludesFirstLevelNodeModules(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "node_modules", ".bin", "trufflehog")
	pkgPath := filepath.Join(tmpDir, "node_modules", "trufflehog-wrapper", "package.json")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(pkgPath), 0o755); err != nil {
		t.Fatalf("failed to create package dir: %v", err)
	}
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to write trufflehog binary: %v", err)
	}
	if err := os.WriteFile(pkgPath, []byte(`{"name":"trufflehog-wrapper","dependencies":{"trufflehog":"1.0.0"}}`), 0o644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	var out bytes.Buffer
	s := New(&Config{
		RootPaths: []string{tmpDir},
		ScanMode:  ScanModeFull,
		Output:    &out,
	})
	s.scanTrufflehog()

	if !hasFindingLocation(s.report.GetFindingsByType(report.FindingTrufflehog), binPath) {
		t.Fatalf("expected TruffleHog binary finding at %s, findings: %+v", binPath, s.report.Findings)
	}
	if !hasFindingLocation(s.report.GetFindingsByType(report.FindingTrufflehogRef), pkgPath) {
		t.Fatalf("expected TruffleHog package reference finding at %s, findings: %+v", pkgPath, s.report.Findings)
	}
}

func hasFindingLocation(findings []report.Finding, location string) bool {
	for _, finding := range findings {
		if finding.Location == location {
			return true
		}
	}
	return false
}

func TestNPMRangeContainsVersion(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		version string
		want    bool
	}{
		{"caret includes later patch", "^1.2.3", "1.2.4", true},
		{"caret includes later minor", "^1.2.3", "1.5.0", true},
		{"caret partial minor includes later patch", "^1.2", "1.2.4", true},
		{"caret partial major includes later minor", "^1", "1.5.0", true},
		{"caret wildcard minor follows partial major range", "^1.x", "1.5.0", true},
		{"caret excludes next major", "^1.2.3", "2.0.0", false},
		{"caret zero major excludes next minor", "^0.2.3", "0.3.0", false},
		{"caret zero major partial minor includes patch", "^0.2", "0.2.9", true},
		{"caret zero major partial minor excludes next minor", "^0.2", "0.3.0", false},
		{"caret zero major partial major includes minor", "^0", "0.5.0", true},
		{"caret zero minor excludes next patch", "^0.0.3", "0.0.4", false},
		{"tilde includes patch", "~1.2.3", "1.2.9", true},
		{"tilde partial minor includes patch", "~1.2", "1.2.9", true},
		{"tilde partial major includes minor", "~1", "1.9.9", true},
		{"tilde wildcard minor follows partial major range", "~1.x", "1.9.9", true},
		{"tilde excludes next minor", "~1.2.3", "1.3.0", false},
		{"tilde partial major excludes next major", "~1", "2.0.0", false},
		{"comparator set includes bounded version", ">=1.2.3 <2.0.0", "1.9.9", true},
		{"comparator set excludes upper bound", ">=1.2.3 <2.0.0", "2.0.0", false},
		{"exact comparator includes same version", "=1.2.3", "1.2.3", true},
		{"unsupported disjunction does not match", "^1.2.3 || ^2.0.0", "1.5.0", false},
		{"unsupported tag does not match", "latest", "1.5.0", false},
		{"prerelease lower than release", ">=1.2.3", "1.2.3-beta.1", false},
		{"build metadata ignored for range ordering", ">=1.2.3 <1.2.4", "1.2.3+build.1", true},
		{"v-prefixed version is supported", "^1.2.3", "v1.2.4", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := npmRangeContainsVersion(tt.spec, tt.version); got != tt.want {
				t.Fatalf("npmRangeContainsVersion(%q, %q) = %v, want %v", tt.spec, tt.version, got, tt.want)
			}
		})
	}
}
