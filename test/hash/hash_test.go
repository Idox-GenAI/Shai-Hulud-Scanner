package hash_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shai-hulud-scanner/pkg/hash"
)

func TestComputeSHA256(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	got, err := hash.ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}
	if got != expectedHash {
		t.Errorf("ComputeSHA256() = %v, want %v", got, expectedHash)
	}
}

func TestComputeSHA256_NonExistentFile(t *testing.T) {
	if _, err := hash.ComputeSHA256("/nonexistent/file/path"); err == nil {
		t.Error("ComputeSHA256() expected error for non-existent file")
	}
}

func TestComputeSHA256_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(testFile, []byte{}, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	got, err := hash.ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}
	if got != expectedHash {
		t.Errorf("ComputeSHA256() = %v, want %v", got, expectedHash)
	}
}

func TestComputeSHA1(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	expectedHash := "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

	got, err := hash.ComputeSHA1(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA1() error = %v", err)
	}
	if got != expectedHash {
		t.Errorf("ComputeSHA1() = %v, want %v", got, expectedHash)
	}
}

func TestComputeSHA1_NonExistentFile(t *testing.T) {
	if _, err := hash.ComputeSHA1("/nonexistent/file/path"); err == nil {
		t.Error("ComputeSHA1() expected error for non-existent file")
	}
}

func TestComputeBothHashes(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	expectedSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	expectedSHA1 := "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

	sha256Hash, sha1Hash, err := hash.ComputeBothHashes(testFile)
	if err != nil {
		t.Fatalf("ComputeBothHashes() error = %v", err)
	}
	if sha256Hash != expectedSHA256 {
		t.Errorf("ComputeBothHashes() sha256 = %v, want %v", sha256Hash, expectedSHA256)
	}
	if sha1Hash != expectedSHA1 {
		t.Errorf("ComputeBothHashes() sha1 = %v, want %v", sha1Hash, expectedSHA1)
	}
}

func TestComputeBothHashes_NonExistentFile(t *testing.T) {
	if _, _, err := hash.ComputeBothHashes("/nonexistent/file/path"); err == nil {
		t.Error("ComputeBothHashes() expected error for non-existent file")
	}
}

func TestComputeSHA256FromReader(t *testing.T) {
	content := "hello world"
	reader := strings.NewReader(content)

	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	got, err := hash.ComputeSHA256FromReader(reader)
	if err != nil {
		t.Fatalf("ComputeSHA256FromReader() error = %v", err)
	}
	if got != expectedHash {
		t.Errorf("ComputeSHA256FromReader() = %v, want %v", got, expectedHash)
	}
}

func TestComputeSHA1FromReader(t *testing.T) {
	content := "hello world"
	reader := strings.NewReader(content)

	expectedHash := "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

	got, err := hash.ComputeSHA1FromReader(reader)
	if err != nil {
		t.Fatalf("ComputeSHA1FromReader() error = %v", err)
	}
	if got != expectedHash {
		t.Errorf("ComputeSHA1FromReader() = %v, want %v", got, expectedHash)
	}
}

func TestComputeSHA256_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "large.bin")

	content := make([]byte, 1024*1024)
	for i := range content {
		content[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	hashValue, err := hash.ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}
	if len(hashValue) != 64 {
		t.Errorf("ComputeSHA256() hash length = %d, want 64", len(hashValue))
	}
}

func TestHashConsistency(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content for consistency check")
	if err := os.WriteFile(testFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	hash1, err := hash.ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}

	hash2, err := hash.ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("ComputeSHA256() inconsistent results: %v != %v", hash1, hash2)
	}

	sha256Both, sha1Both, err := hash.ComputeBothHashes(testFile)
	if err != nil {
		t.Fatalf("ComputeBothHashes() error = %v", err)
	}
	if hash1 != sha256Both {
		t.Errorf("SHA256 mismatch between ComputeSHA256 and ComputeBothHashes: %v != %v", hash1, sha256Both)
	}

	sha1Single, err := hash.ComputeSHA1(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA1() error = %v", err)
	}
	if sha1Single != sha1Both {
		t.Errorf("SHA1 mismatch between ComputeSHA1 and ComputeBothHashes: %v != %v", sha1Single, sha1Both)
	}
}
