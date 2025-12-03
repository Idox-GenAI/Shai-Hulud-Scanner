package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func ComputeSHA256(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func ComputeSHA1(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	h := sha1.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeBothHashes computes both SHA256 and SHA1 hashes of a file in a single read.
func ComputeBothHashes(filepath string) (sha256Hash, sha1Hash string, err error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	h256 := sha256.New()
	h1 := sha1.New()
	w := io.MultiWriter(h256, h1)

	if _, err := io.Copy(w, f); err != nil {
		return "", "", fmt.Errorf("failed to compute hashes: %w", err)
	}

	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h1.Sum(nil)), nil
}

// ComputeSHA256FromReader computes the SHA256 hash from an io.Reader.
func ComputeSHA256FromReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeSHA1FromReader computes the SHA1 hash from an io.Reader.
func ComputeSHA1FromReader(r io.Reader) (string, error) {
	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
