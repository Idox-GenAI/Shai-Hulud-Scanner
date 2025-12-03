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
	FindingNodeModules        FindingType = "node_modules"
	FindingNpmCache           FindingType = "npm-cache"
	FindingFileArtefact       FindingType = "file-artefact"
	FindingGitBranch          FindingType = "git-branch"
	FindingGitRemote          FindingType = "git-remote"
	FindingWorkflowPattern    FindingType = "workflow-pattern"
	FindingWorkflowContent    FindingType = "workflow-content"
	FindingCredentialFile     FindingType = "credential-file"
	FindingMaliciousRunner    FindingType = "malicious-runner"
	FindingRunnerInstallation FindingType = "runner-installation"
	FindingPostinstallHook    FindingType = "postinstall-hook"
	FindingMalwareHash        FindingType = "malware-hash"
	FindingMigrationAttack    FindingType = "migration-attack"
	FindingTrufflehog         FindingType = "trufflehog-installation"
	FindingTrufflehogRef      FindingType = "trufflehog-reference"
	FindingEnvExfil           FindingType = "env-exfil-pattern"
)

// Finding represents a single detection finding.
type Finding struct {
	Type      FindingType
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

// AddFinding adds a finding to the report.
func (r *Report) AddFinding(findingType FindingType, indicator, location string) {
	r.Findings = append(r.Findings, Finding{
		Type:      findingType,
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
		sb.WriteString(fmt.Sprintf("Indicators of compromise detected: %d\n", r.FindingCount()))
		sb.WriteString("\n")
		for _, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("Type: %s | Indicator: %s | Location: %s\n", f.Type, f.Indicator, f.Location))
		}
	}

	_, err := w.Write([]byte(sb.String()))
	return err
}

// PrintSummary prints a summary of the findings to stdout.
func (r *Report) PrintSummary(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---- Summary ----")
	fmt.Fprintf(w, "[*] Scan completed in %s (%s mode)\n", r.Duration.Round(time.Second), strings.ToUpper(r.ScanMode))

	if !r.HasFindings() {
		fmt.Fprintln(w, "[OK] No indicators of Shai-Hulud compromise were found in the scanned locations.")
	} else {
		fmt.Fprintf(w, "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: %d item(s)\n", r.FindingCount())
		for _, f := range r.Findings {
			fmt.Fprintln(w, f.String())
		}
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

// IsCritical returns true if any critical findings (malware hash, malicious runner) were detected.
func (r *Report) IsCritical() bool {
	for _, f := range r.Findings {
		if f.Type == FindingMalwareHash || f.Type == FindingMaliciousRunner {
			return true
		}
	}
	return false
}
