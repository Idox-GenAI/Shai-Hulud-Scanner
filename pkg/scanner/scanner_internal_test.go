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
