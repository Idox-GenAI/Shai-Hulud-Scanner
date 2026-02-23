// Package config provides configuration parsing for the scanner.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"shai-hulud-scanner/pkg/report"
)

// Allowlist contains configuration for excluding findings from the scan.
type Allowlist struct {
	// AllowPackages lists package names that should be excluded from detection.
	// Supports glob patterns like "@cypress/*" or "core-js".
	AllowPackages []string `json:"allowPackages"`

	// AllowPaths lists path patterns that should be excluded from detection.
	// Supports glob patterns like "**/cypress/**" or "**/node_modules/core-js/**".
	AllowPaths []string `json:"allowPaths"`

	// DisableFindingTypes lists finding types that should be completely disabled.
	// Valid values: credential-file, env-exfil-pattern, postinstall-hook, etc.
	DisableFindingTypes []string `json:"disableFindingTypes"`
}

// LoadAllowlist loads an allowlist configuration from a JSON file.
func LoadAllowlist(path string) (*Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var allowlist Allowlist
	if err := json.Unmarshal(data, &allowlist); err != nil {
		return nil, err
	}

	return &allowlist, nil
}

// IsPackageAllowed checks if a package name matches any allowlist pattern.
func (a *Allowlist) IsPackageAllowed(pkgName string) bool {
	if a == nil {
		return false
	}

	for _, pattern := range a.AllowPackages {
		if matchPattern(pattern, pkgName) {
			return true
		}
	}
	return false
}

// IsPathAllowed checks if a path matches any allowlist pattern.
func (a *Allowlist) IsPathAllowed(path string) bool {
	if a == nil {
		return false
	}

	// Normalize path separators
	normalizedPath := filepath.ToSlash(path)

	for _, pattern := range a.AllowPaths {
		normalizedPattern := filepath.ToSlash(pattern)
		if matchGlobPattern(normalizedPattern, normalizedPath) {
			return true
		}
	}
	return false
}

// IsFindingTypeDisabled checks if a finding type is disabled.
func (a *Allowlist) IsFindingTypeDisabled(ft report.FindingType) bool {
	if a == nil {
		return false
	}

	ftStr := string(ft)
	for _, disabled := range a.DisableFindingTypes {
		if strings.EqualFold(disabled, ftStr) {
			return true
		}
	}
	return false
}

// ShouldSkipFinding checks if a finding should be skipped based on the allowlist.
func (a *Allowlist) ShouldSkipFinding(ft report.FindingType, indicator, location string) bool {
	if a == nil {
		return false
	}

	// Check if finding type is disabled
	if a.IsFindingTypeDisabled(ft) {
		return true
	}

	// Check if path is allowed
	if a.IsPathAllowed(location) {
		return true
	}

	// For package-related findings, check if package is allowed
	if ft == report.FindingNodeModules || ft == report.FindingNpmCache {
		if a.IsPackageAllowed(indicator) {
			return true
		}
	}

	return false
}

// matchPattern performs simple pattern matching with wildcard support.
// Supports patterns like "core-js", "@cypress/*", "*-loader".
func matchPattern(pattern, value string) bool {
	// Exact match
	if pattern == value {
		return true
	}

	// Check for wildcard patterns
	if strings.Contains(pattern, "*") {
		return matchWildcard(pattern, value)
	}

	return false
}

// matchWildcard performs wildcard matching.
func matchWildcard(pattern, value string) bool {
	// Handle @scope/* pattern
	if before, ok := strings.CutSuffix(pattern, "/*"); ok {
		prefix := before
		if strings.HasPrefix(value, prefix+"/") {
			return true
		}
	}

	// Handle *-suffix pattern
	if after, ok := strings.CutPrefix(pattern, "*"); ok {
		suffix := after
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}

	// Handle prefix-* pattern
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		prefix := before
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	return false
}

// matchGlobPattern performs glob-style pattern matching for paths.
func matchGlobPattern(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	return matchGlobPathSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchGlobPathSegments(patternSegs, pathSegs []string) bool {
	if len(patternSegs) == 0 {
		return len(pathSegs) == 0
	}

	if patternSegs[0] == "**" {
		// Collapse consecutive ** to avoid redundant recursion.
		for len(patternSegs) > 1 && patternSegs[1] == "**" {
			patternSegs = patternSegs[1:]
		}
		if len(patternSegs) == 1 {
			return true
		}
		for i := 0; i <= len(pathSegs); i++ {
			if matchGlobPathSegments(patternSegs[1:], pathSegs[i:]) {
				return true
			}
		}
		return false
	}

	if len(pathSegs) == 0 {
		return false
	}
	if !matchGlobPathSegment(patternSegs[0], pathSegs[0]) {
		return false
	}
	return matchGlobPathSegments(patternSegs[1:], pathSegs[1:])
}

func matchGlobPathSegment(pattern, segment string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == segment
	}

	parts := strings.Split(pattern, "*")
	pos := 0

	// Prefix anchor
	if first := parts[0]; first != "" {
		if !strings.HasPrefix(segment, first) {
			return false
		}
		pos = len(first)
	}

	// Middle fragments
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(segment[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}

	// Suffix anchor
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	if !strings.HasSuffix(segment, last) {
		return false
	}

	// Ensure the suffix occurs after the matched prefix/middle sequence.
	suffixPos := len(segment) - len(last)
	return suffixPos >= pos
}
