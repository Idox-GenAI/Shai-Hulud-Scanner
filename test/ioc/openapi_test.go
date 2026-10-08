package ioc_test

import (
	"strings"
	"testing"

	"shai-hulud-scanner/pkg/ioc"
)

func TestOpenAPISecretDumpWorkflowRequiresCombinedIndicators(t *testing.T) {
	workflow := `name: "ClaudeCode Review"
on: [deployment]
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      DATA: ${{ toJSON( secrets ) }}
    steps:
      - uses: actions/upload-artifact@inert-test-reference
        with:
          path: 'res.txt'
`
	for _, test := range []struct {
		name    string
		content string
		want    bool
	}{
		{"reported combination", workflow, true},
		{"Windows line endings", strings.ReplaceAll(workflow, "\n", "\r\n"), true},
		{"ordinary review", strings.ReplaceAll(workflow, "toJSON( secrets )", "toJSON(vars)"), false},
		{"different workflow", strings.ReplaceAll(workflow, "ClaudeCode Review", "Build"), false},
		{"different result path", strings.ReplaceAll(workflow, "res.txt", "coverage.txt"), false},
		{"no artifact upload", strings.ReplaceAll(workflow, "actions/upload-artifact@", "example/action@"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ioc.IsOpenAPISecretDumpWorkflow(test.content); got != test.want {
				t.Errorf("IsOpenAPISecretDumpWorkflow() = %t, want %t", got, test.want)
			}
		})
	}
}
