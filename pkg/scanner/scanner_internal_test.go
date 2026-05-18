package scanner

import (
	"os"
	"path/filepath"
	"testing"
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
		{"caret excludes next major", "^1.2.3", "2.0.0", false},
		{"caret zero major excludes next minor", "^0.2.3", "0.3.0", false},
		{"caret zero major partial minor includes patch", "^0.2", "0.2.9", true},
		{"caret zero major partial minor excludes next minor", "^0.2", "0.3.0", false},
		{"caret zero major partial major includes minor", "^0", "0.5.0", true},
		{"caret zero minor excludes next patch", "^0.0.3", "0.0.4", false},
		{"tilde includes patch", "~1.2.3", "1.2.9", true},
		{"tilde partial minor includes patch", "~1.2", "1.2.9", true},
		{"tilde partial major includes minor", "~1", "1.9.9", true},
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
