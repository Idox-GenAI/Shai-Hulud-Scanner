package ioc

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// PackageFeedURLs contains URLs that provide lists of compromised npm packages.
var PackageFeedURLs = []string{
	"https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv",
}

// MaliciousFileNames contains known Shai-Hulud artifact filenames (workflows/payloads).
var MaliciousFileNames = []string{
	// Original Shai-Hulud (September 2025)
	"shai-hulud.js",
	"shai_hulud.js",
	"shai-hulud-workflow.yml",
	"shai_hulud_workflow.yml",
	"shai-hulud.yml",
	"shai_hulud.yml",
	// Shai-Hulud 2.0 (November 2025)
	"setup_bun.js",
	"bun_environment.js",
	"discussion.yaml",
	// Exfiltration artifacts
	"truffleSecrets.json",
	"actionsSecrets.json",
}

// SuspiciousBranchPatterns contains git branch name patterns associated with Shai-Hulud.
var SuspiciousBranchPatterns = []string{
	"shai-hulud",
	"shai_hulud",
	"SHA1HULUD",
}

// SuspiciousWorkflowPatterns contains patterns found in malicious GitHub Actions workflows.
var SuspiciousWorkflowPatterns = []string{
	"self-hosted",
	"SHA1HULUD",
	"shai-hulud",
	"shai_hulud",
	"webhook.site",
	"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
}

// CloudCredentialPaths contains relative paths to cloud credential files.
var CloudCredentialPaths = []string{
	".aws/credentials",
	".aws/config",
	".azure",
	".npmrc",
	".env",
}

// SuspiciousHookPatterns contains patterns that indicate potentially malicious postinstall hooks.
var SuspiciousHookPatterns = []string{
	"curl ",
	"wget ",
	"eval(",
	"node -e",
	"base64",
	"webhook",
	"exfil",
	"/tmp/",
	"\\temp\\",
	"powershell",
	"cmd /c",
}

// SuspiciousFileNames contains filenames that should be checked for malware hashes.
var SuspiciousFileNames = []string{
	"bundle.js",
	"setup_bun.js",
	"bun_environment.js",
	"shai-hulud.js",
	"shai_hulud.js",
}

// MaliciousSHA256 maps known malicious SHA256 hashes to their descriptions.
var MaliciousSHA256 = map[string]string{
	"46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09": "Shai-Hulud bundle.js payload",
	"b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777": "Shai-Hulud malicious file",
	"dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c": "Shai-Hulud malicious file",
	"4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db": "Shai-Hulud malicious file",
}

// MaliciousSHA1 maps known malicious SHA1 hashes to their descriptions (Shai-Hulud 2.0).
var MaliciousSHA1 = map[string]string{
	"d1829b4708126dcc7bea7437c04d1f10eacd4a16": "setup_bun.js (Shai-Hulud 2.0)",
	"d60ec97eea19fffb4809bc35b91033b52490ca11": "bun_environment.js (Shai-Hulud 2.0)",
	"3d7570d14d34b0ba137d502f042b27b0f37a59fa": "bun_environment.js variant (Shai-Hulud 2.0)",
}

// EnvAccessPatterns contains patterns that indicate environment variable access.
var EnvAccessPatterns = []string{
	"process.env",
	"os.environ",
	"$env:",
	"AWS_ACCESS_KEY",
	"AWS_SECRET",
	"GITHUB_TOKEN",
	"NPM_TOKEN",
	"GH_TOKEN",
	"AZURE_",
}

// ExfilPatterns contains patterns that indicate potential data exfiltration.
var ExfilPatterns = []string{
	"webhook.site",
	"bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
	"exfiltrat",
	"fetch(",
	"axios.",
	"http.request",
	"https.request",
}

// HookNames contains npm lifecycle hook names to check for suspicious patterns.
var HookNames = []string{
	"postinstall",
	"preinstall",
	"install",
	"prepare",
}

// RunnerDirPatterns contains directory name patterns for GitHub Actions runners.
var RunnerDirPatterns = []string{
	"actions-runner",
	"_work",
	"runner",
}

// PackageVersionConstraint represents a compromised package and the set of
// version values (or constraints) that should be treated as malicious.
//
// The Wiz feed shai-hulud-2-packages.csv uses a "Package,Version" format
// where the Version column can contain one or more entries separated by
// "||", for example:
//
//	02-echo,= 0.0.7
//	@scope/pkg,= 1.2.3 || = 1.2.4
//
// ParsePackageCSV normalises these into individual version strings such as
// "0.0.7" or "1.2.3" / "1.2.4" and keeps the original raw specification
// in RawSpec for reference.
type PackageVersionConstraint struct {
	Package  string   // npm package name (scoped or unscoped)
	Versions []string // individual version values extracted from the CSV
	RawSpec  string   // raw Version cell content from the CSV
}

// ParsePackageCSV parses a Wiz style CSV feed containing compromised npm
// packages and the versions that need to be checked for.
//
// The expected format is:
//
//	Package,Version
//	package-name,= 0.0.7
//	@scope/name,= 1.2.3 || = 1.2.4
//
// Header detection is case-insensitive. Empty lines and records without both
// package and version data are skipped.
func ParsePackageCSV(r io.Reader) ([]PackageVersionConstraint, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	// Allow records with a variable number of fields so that malformed or
	// partial lines do not cause a hard parse failure. We will validate the
	// number of fields per record ourselves.
	reader.FieldsPerRecord = -1

	var constraints []PackageVersionConstraint
	row := 0
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse package CSV: %w", err)
		}
		row++

		if len(rec) == 0 {
			continue
		}

		// Skip header row if present (case-insensitive match on first two columns).
		if row == 1 && len(rec) >= 2 {
			h0 := strings.TrimSpace(strings.ToLower(rec[0]))
			h1 := strings.TrimSpace(strings.ToLower(rec[1]))
			if h0 == "package" && h1 == "version" {
				continue
			}
		}

		if len(rec) < 2 {
			continue
		}

		name := strings.TrimSpace(rec[0])
		versionSpec := strings.TrimSpace(rec[1])
		if name == "" || versionSpec == "" {
			continue
		}

		versions := parseVersionSpec(versionSpec)
		if len(versions) == 0 {
			// If we can't extract any versions, skip this record instead of
			// creating an ambiguous entry.
			continue
		}

		constraints = append(constraints, PackageVersionConstraint{
			Package:  name,
			Versions: versions,
			RawSpec:  versionSpec,
		})
	}

	return constraints, nil
}

// parseVersionSpec takes a Version cell from the Wiz CSV (for example,
// "= 0.0.7" or "= 0.6.1 || = 0.6.2") and returns the individual version
// values as a slice of strings (e.g. ["0.0.7"] or ["0.6.1", "0.6.2"]).
func parseVersionSpec(spec string) []string {
	var versions []string
	if spec == "" {
		return versions
	}

	parts := strings.Split(spec, "||")
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		// Strip leading '=' used in the feed (e.g. "= 0.0.7").
		if strings.HasPrefix(p, "=") {
			p = strings.TrimSpace(p[1:])
		}
		if p == "" {
			continue
		}
		versions = append(versions, p)
	}

	return versions
}

// IsMaliciousSHA256 checks if a SHA256 hash is known to be malicious.
func IsMaliciousSHA256(hash string) (string, bool) {
	desc, ok := MaliciousSHA256[hash]
	return desc, ok
}

// IsMaliciousSHA1 checks if a SHA1 hash is known to be malicious.
func IsMaliciousSHA1(hash string) (string, bool) {
	desc, ok := MaliciousSHA1[hash]
	return desc, ok
}

// IsMaliciousFileName checks if a filename matches known malicious filenames.
func IsMaliciousFileName(name string) bool {
	for _, malName := range MaliciousFileNames {
		if name == malName {
			return true
		}
	}
	return false
}

// IsSuspiciousFileName checks if a filename should be hash-checked.
func IsSuspiciousFileName(name string) bool {
	for _, susName := range SuspiciousFileNames {
		if name == susName {
			return true
		}
	}
	return false
}

// ContainsSuspiciousBranchPattern checks if a branch name contains suspicious patterns.
func ContainsSuspiciousBranchPattern(branchName string) bool {
	for _, pattern := range SuspiciousBranchPatterns {
		if containsIgnoreCase(branchName, pattern) {
			return true
		}
	}
	return false
}

// ContainsSuspiciousWorkflowPattern checks if content contains suspicious workflow patterns.
func ContainsSuspiciousWorkflowPattern(content string) (string, bool) {
	for _, pattern := range SuspiciousWorkflowPatterns {
		if containsIgnoreCase(content, pattern) {
			return pattern, true
		}
	}
	return "", false
}

// ContainsSuspiciousHookPattern checks if a hook script contains suspicious patterns.
func ContainsSuspiciousHookPattern(script string) (string, bool) {
	for _, pattern := range SuspiciousHookPatterns {
		if containsIgnoreCase(script, pattern) {
			return pattern, true
		}
	}
	return "", false
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(substr) > 0 &&
				(indexOf(toLower(s), toLower(substr)) >= 0))
}

// toLower converts a string to lowercase without importing strings package.
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// indexOf finds the index of substr in s, returns -1 if not found.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
