// Package report provides finding types and report generation for the scanner.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// FindingType represents the type of finding detected.
type FindingType string

const (
	FindingNodeModules         FindingType = "node_modules"
	FindingNpmCache            FindingType = "npm-cache"
	FindingFileArtifact        FindingType = "file-artifact"
	FindingGitBranch           FindingType = "git-branch"
	FindingGitRemote           FindingType = "git-remote"
	FindingWorkflowPattern     FindingType = "workflow-pattern"
	FindingWorkflowContent     FindingType = "workflow-content"
	FindingCredentialFile      FindingType = "credential-file"
	FindingMaliciousRunner     FindingType = "malicious-runner"
	FindingRunnerInstallation  FindingType = "runner-installation"
	FindingPostinstallHook     FindingType = "postinstall-hook"
	FindingMalwareHash         FindingType = "malware-hash"
	FindingMigrationAttack     FindingType = "migration-attack"
	FindingTrufflehog          FindingType = "trufflehog-installation"
	FindingTrufflehogRef       FindingType = "trufflehog-reference"
	FindingEnvExfil            FindingType = "env-exfil-pattern"
	FindingCompromisedNS       FindingType = "compromised-namespace"
	FindingLockfileCompromised FindingType = "lockfile-compromised"
	FindingPackageJSONComp     FindingType = "package-json-compromised"
)

// FindingSeverity represents the severity level of a finding.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical" // Confirmed malware (hash match, malicious runner)
	SeverityHigh     FindingSeverity = "high"     // Known bad package/file, specific IOCs
	SeverityWarning  FindingSeverity = "warning"  // Needs review, may be false positive
)

// findingSeverityMap maps finding types to their default severity levels.
var findingSeverityMap = map[FindingType]FindingSeverity{
	FindingMalwareHash:         SeverityCritical,
	FindingMaliciousRunner:     SeverityCritical,
	FindingNodeModules:         SeverityHigh,
	FindingNpmCache:            SeverityHigh,
	FindingFileArtifact:        SeverityHigh,
	FindingGitBranch:           SeverityHigh,
	FindingGitRemote:           SeverityHigh,
	FindingWorkflowPattern:     SeverityHigh,
	FindingLockfileCompromised: SeverityHigh,
	FindingPackageJSONComp:     SeverityHigh,
	FindingWorkflowContent:     SeverityWarning,
	FindingCredentialFile:      SeverityWarning,
	FindingRunnerInstallation:  SeverityWarning,
	FindingPostinstallHook:     SeverityWarning,
	FindingMigrationAttack:     SeverityWarning,
	FindingTrufflehog:          SeverityWarning,
	FindingTrufflehogRef:       SeverityWarning,
	FindingEnvExfil:            SeverityWarning,
	FindingCompromisedNS:       SeverityWarning,
}

// GetDefaultSeverity returns the default severity for a finding type.
func GetDefaultSeverity(ft FindingType) FindingSeverity {
	if sev, ok := findingSeverityMap[ft]; ok {
		return sev
	}
	return SeverityWarning
}

// Finding represents a single detection finding.
type Finding struct {
	Type      FindingType
	Severity  FindingSeverity
	Indicator string
	Location  string
}

// String returns a formatted string representation of the finding.
func (f Finding) String() string {
	return fmt.Sprintf("%-18s %-40s %s", f.Type, f.Indicator, f.Location)
}

// Report contains all findings from a scan and metadata.
type Report struct {
	Timestamp           time.Time
	ScanMode            string
	Duration            time.Duration
	PathsScanned        []string
	CompromisedPkgCount int
	Findings            []Finding
}

// NewReport creates a new report with the given metadata.
func NewReport(scanMode string, pathsScanned []string) *Report {
	return &Report{
		Timestamp:    time.Now().UTC(),
		ScanMode:     scanMode,
		PathsScanned: pathsScanned,
		Findings:     make([]Finding, 0),
	}
}

// AddFinding adds a finding to the report with default severity.
func (r *Report) AddFinding(findingType FindingType, indicator, location string) {
	r.Findings = append(r.Findings, Finding{
		Type:      findingType,
		Severity:  GetDefaultSeverity(findingType),
		Indicator: indicator,
		Location:  location,
	})
}

// AddFindingWithSeverity adds a finding with a specific severity override.
func (r *Report) AddFindingWithSeverity(findingType FindingType, severity FindingSeverity, indicator, location string) {
	r.Findings = append(r.Findings, Finding{
		Type:      findingType,
		Severity:  severity,
		Indicator: indicator,
		Location:  location,
	})
}

// SetDuration sets the scan duration.
func (r *Report) SetDuration(d time.Duration) {
	r.Duration = d
}

// SetCompromisedPackageCount sets the count of loaded compromised packages.
func (r *Report) SetCompromisedPackageCount(count int) {
	r.CompromisedPkgCount = count
}

// HasFindings returns true if any findings were detected.
func (r *Report) HasFindings() bool {
	return len(r.Findings) > 0
}

// FindingCount returns the number of findings.
func (r *Report) FindingCount() int {
	return len(r.Findings)
}

// WriteToFile writes the report to a file.
func (r *Report) WriteToFile(filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	return r.Write(f)
}

// Write writes the report to an io.Writer.
func (r *Report) Write(w io.Writer) error {
	var sb strings.Builder

	sb.WriteString("Shai-Hulud Dynamic Detection Report\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", r.Timestamp.Format("2006-01-02 15:04:05Z")))
	sb.WriteString(fmt.Sprintf("Scan Mode: %s\n", strings.ToUpper(r.ScanMode)))
	sb.WriteString(fmt.Sprintf("Scan Duration: %s\n", r.Duration.Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Paths Scanned: %s\n", strings.Join(r.PathsScanned, ", ")))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Compromised packages loaded: %d\n", r.CompromisedPkgCount))
	sb.WriteString("\n")

	if !r.HasFindings() {
		sb.WriteString("No indicators of compromise found in scanned locations.\n")
	} else {
		critical, high, warning := r.CountBySeverity()
		sb.WriteString(fmt.Sprintf("Findings Summary: %d critical, %d high, %d warnings\n", critical, high, warning))
		sb.WriteString("\n")

		if critical > 0 {
			sb.WriteString("=== CRITICAL FINDINGS (confirmed malware) ===\n")
			for _, f := range r.GetFindingsBySeverity(SeverityCritical) {
				sb.WriteString(fmt.Sprintf("Type: %s | Indicator: %s | Location: %s\n", f.Type, f.Indicator, f.Location))
			}
			sb.WriteString("\n")
		}

		if high > 0 {
			sb.WriteString("=== HIGH CONFIDENCE DETECTIONS (requires action) ===\n")
			for _, f := range r.GetFindingsBySeverity(SeverityHigh) {
				sb.WriteString(fmt.Sprintf("Type: %s | Indicator: %s | Location: %s\n", f.Type, f.Indicator, f.Location))
			}
			sb.WriteString("\n")
		}

		if warning > 0 {
			sb.WriteString("=== WARNINGS (review recommended, may be false positives) ===\n")
			for _, f := range r.GetFindingsBySeverity(SeverityWarning) {
				sb.WriteString(fmt.Sprintf("Type: %s | Indicator: %s | Location: %s\n", f.Type, f.Indicator, f.Location))
			}
			sb.WriteString("\n")
		}
	}

	_, err := w.Write([]byte(sb.String()))
	return err
}

// PrintSummary prints a summary of the findings to stdout, grouped by severity.
func (r *Report) PrintSummary(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---- Scan Results ----")
	fmt.Fprintf(w, "[*] Scan completed in %s (%s mode)\n", r.Duration.Round(time.Second), strings.ToUpper(r.ScanMode))
	fmt.Fprintln(w)

	if !r.HasFindings() {
		fmt.Fprintln(w, "[OK] No indicators of Shai-Hulud compromise were found in the scanned locations.")
		return
	}

	critical, high, warning := r.CountBySeverity()

	// Critical findings
	if critical > 0 {
		fmt.Fprintf(w, "[!!!] CRITICAL FINDINGS: %d (confirmed malware)\n", critical)
		for _, f := range r.GetFindingsBySeverity(SeverityCritical) {
			fmt.Fprintf(w, "  [%s] %s\n", f.Type, f.Indicator)
			fmt.Fprintf(w, "         %s\n", f.Location)
		}
		fmt.Fprintln(w)
	}

	// High severity findings
	if high > 0 {
		fmt.Fprintf(w, "[!!] HIGH CONFIDENCE DETECTIONS: %d (requires action)\n", high)
		for _, f := range r.GetFindingsBySeverity(SeverityHigh) {
			fmt.Fprintf(w, "  [%s] %s\n", f.Type, f.Indicator)
			fmt.Fprintf(w, "         %s\n", f.Location)
		}
		fmt.Fprintln(w)
	}

	// Warning findings
	if warning > 0 {
		fmt.Fprintf(w, "[!] WARNINGS: %d (review recommended, may be false positives)\n", warning)
		for _, f := range r.GetFindingsBySeverity(SeverityWarning) {
			fmt.Fprintf(w, "  [%s] %s\n", f.Type, f.Indicator)
			fmt.Fprintf(w, "         %s\n", f.Location)
		}
		fmt.Fprintln(w)
	}

	// Print helpful note if only warnings
	if critical == 0 && high == 0 && warning > 0 {
		fmt.Fprintln(w, "NOTE: Only warnings were found. Common packages like core-js, cypress, and")
		fmt.Fprintln(w, "      angular may trigger these. Use --strict to fail on warnings.")
	}
}

// GetFindingsByType returns all findings of a specific type.
func (r *Report) GetFindingsByType(t FindingType) []Finding {
	var result []Finding
	for _, f := range r.Findings {
		if f.Type == t {
			result = append(result, f)
		}
	}
	return result
}

// IsCritical returns true if any critical severity findings were detected.
func (r *Report) IsCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHighSeverity returns true if any high severity findings were detected.
func (r *Report) HasHighSeverity() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any warning severity findings were detected.
func (r *Report) HasWarnings() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// GetFindingsBySeverity returns all findings of a specific severity.
func (r *Report) GetFindingsBySeverity(sev FindingSeverity) []Finding {
	var result []Finding
	for _, f := range r.Findings {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

// CountBySeverity returns the count of findings for each severity level.
func (r *Report) CountBySeverity() (critical, high, warning int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			critical++
		case SeverityHigh:
			high++
		case SeverityWarning:
			warning++
		}
	}
	return
}
