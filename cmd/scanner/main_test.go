package main

import (
	"testing"

	"shai-hulud-scanner/pkg/report"
)

func TestExitCodeForReport(t *testing.T) {
	tests := []struct {
		name            string
		buildReport     func() *report.Report
		strict          bool
		warnOnly        bool
		reportWriteFail bool
		want            int
	}{
		{
			name: "clean scan with report write failure exits 1",
			buildReport: func() *report.Report {
				return report.NewReport("quick", []string{"/tmp"})
			},
			reportWriteFail: true,
			want:            1,
		},
		{
			name: "warnings only with warn-only and no write error exits 0",
			buildReport: func() *report.Report {
				r := report.NewReport("quick", []string{"/tmp"})
				r.AddFinding(report.FindingCredentialFile, ".env", "/tmp/.env")
				return r
			},
			warnOnly: true,
			want:     0,
		},
		{
			name: "high severity in warn-only exits 1",
			buildReport: func() *report.Report {
				r := report.NewReport("quick", []string{"/tmp"})
				r.AddFinding(report.FindingNodeModules, "bad-pkg", "/tmp/node_modules/bad-pkg")
				return r
			},
			warnOnly: true,
			want:     1,
		},
		{
			name: "warnings in strict mode exit 1",
			buildReport: func() *report.Report {
				r := report.NewReport("quick", []string{"/tmp"})
				r.AddFinding(report.FindingCredentialFile, ".env", "/tmp/.env")
				return r
			},
			strict: true,
			want:   1,
		},
		{
			name: "critical findings keep exit code 2 even if report write fails",
			buildReport: func() *report.Report {
				r := report.NewReport("quick", []string{"/tmp"})
				r.AddFinding(report.FindingMalwareHash, "SHA256 match", "/tmp/bad.js")
				return r
			},
			reportWriteFail: true,
			want:            2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCodeForReport(tt.buildReport(), tt.strict, tt.warnOnly, tt.reportWriteFail)
			if got != tt.want {
				t.Fatalf("exitCodeForReport() = %d, want %d", got, tt.want)
			}
		})
	}
}
