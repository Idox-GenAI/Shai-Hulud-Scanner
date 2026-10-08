package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"shai-hulud-scanner/pkg/config"
	pkghash "shai-hulud-scanner/pkg/hash"
	"shai-hulud-scanner/pkg/ioc"
	"shai-hulud-scanner/pkg/report"
)

func TestTensorlakePackageDetectionOffline(t *testing.T) {
	originalURLs := ioc.PackageFeedURLs
	ioc.PackageFeedURLs = nil
	t.Cleanup(func() { ioc.PackageFeedURLs = originalURLs })

	for _, mode := range []ScanMode{ScanModeQuick, ScanModeFull} {
		for _, version := range []string{"0.5.143", "0.5.144", "0.5.145"} {
			t.Run(string(mode)+"/"+version, func(t *testing.T) {
				root := t.TempDir()
				writeTensorlakeFixture(t, root, "node_modules/tensorlake/package.json", fmt.Sprintf(`{"name":"tensorlake","version":%q}`, version))
				writeTensorlakeFixture(t, root, "package.json", fmt.Sprintf(`{"dependencies":{"tensorlake":%q}}`, version))
				writeTensorlakeFixture(t, root, "package-lock.json", fmt.Sprintf(`{"lockfileVersion":3,"packages":{"node_modules/tensorlake":{"version":%q}}}`, version))
				s := New(&Config{RootPaths: []string{root}, ScanMode: mode, Output: io.Discard})
				if err := s.loadCompromisedPackages(); err != nil {
					t.Fatal(err)
				}
				s.scanNodeModules([]string{filepath.Join(root, "node_modules")})
				s.checkPackageJson(filepath.Join(root, "package.json"))
				s.scanLockfiles()

				want := 0
				if version == "0.5.144" {
					want = 1
				}
				for _, findingType := range []report.FindingType{report.FindingNodeModules, report.FindingPackageJSONComp, report.FindingLockfileCompromised} {
					findings := s.report.GetFindingsByType(findingType)
					if len(findings) != want {
						t.Errorf("%s findings = %+v, want %d", findingType, findings, want)
					}
					for _, finding := range findings {
						if finding.Severity != report.SeverityHigh {
							t.Errorf("severity = %s, want high", finding.Severity)
						}
					}
				}
			})
		}
	}
}

func TestTensorlakeArtifactPaths(t *testing.T) {
	for _, mode := range []ScanMode{ScanModeQuick, ScanModeFull} {
		t.Run(string(mode), func(t *testing.T) {
			root := t.TempDir()
			paths := []string{
				"Math_Symbol.js",
				"tmp.ts018051808.lock",
				".local/bin/gh-token-monitor.sh",
				".config/systemd/user/gh-token-monitor.service",
				"AppData/Local/gh-token-monitor/monitor.ps1",
			}
			for _, path := range paths {
				writeTensorlakeFixture(t, root, path, "inert artifact fixture")
			}
			for _, path := range []string{"setup.mjs", "runtime.cjs", "monitor.ps1", "AppData/Local/legitimate/monitor.ps1"} {
				writeTensorlakeFixture(t, root, path, "benign fixture")
			}
			s := New(&Config{RootPaths: []string{root}, ScanMode: mode, Output: io.Discard})
			s.scanMaliciousFiles()
			findings := s.report.GetFindingsByType(report.FindingFileArtifact)
			if len(findings) != len(paths) {
				t.Fatalf("artifact findings = %+v, want %d", findings, len(paths))
			}
			for _, path := range paths {
				if !hasFindingLocation(findings, filepath.Join(root, filepath.FromSlash(path))) {
					t.Errorf("missing artifact %s", path)
				}
			}
			if _, high, _ := s.report.CountBySeverity(); high != len(paths) {
				t.Errorf("expected all artifact findings to have high severity")
			}
		})
	}
}

func TestTensorlakeHashCandidates(t *testing.T) {
	// Inert bytes exercise traversal and both hash algorithms without malware samples.
	content := []byte("inert tensorlake hash fixture")
	sha256, err := pkghash.ComputeSHA256FromReader(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	sha1, err := pkghash.ComputeSHA1FromReader(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ScanMode{ScanModeQuick, ScanModeFull} {
		for _, algorithm := range []string{"SHA256", "SHA1"} {
			t.Run(string(mode)+"/"+algorithm, func(t *testing.T) {
				hashes, hash := ioc.MaliciousSHA256, sha256
				if algorithm == "SHA1" {
					hashes, hash = ioc.MaliciousSHA1, sha1
				}
				original, existed := hashes[hash]
				hashes[hash] = "inert tensorlake fixture"
				t.Cleanup(func() {
					if existed {
						hashes[hash] = original
					} else {
						delete(hashes, hash)
					}
				})
				root := t.TempDir()
				paths := []string{"node_modules/tensorlake/lib/setup.mjs", "node_modules/tensorlake/lib/Math_Symbol.js", "tensorlake-0.5.144.tgz"}
				if mode == ScanModeFull {
					paths = append(paths, "renamed-loader.mjs", "renamed-payload.cjs", "renamed-package.tgz")
				}
				for _, path := range paths {
					writeTensorlakeFixture(t, root, path, string(content))
				}
				writeTensorlakeFixture(t, root, "benign/setup.mjs", "export const setup = true;")
				s := New(&Config{RootPaths: []string{root}, ScanMode: mode, Output: io.Discard})
				s.scanHashes()
				findings := s.report.GetFindingsByType(report.FindingMalwareHash)
				if len(findings) != len(paths) {
					t.Fatalf("hash findings = %+v, want %d", findings, len(paths))
				}
				for _, path := range paths {
					if !hasFindingLocation(findings, filepath.Join(root, filepath.FromSlash(path))) {
						t.Errorf("missing hash match for %s", path)
					}
				}
				if critical, _, _ := s.report.CountBySeverity(); critical != len(paths) {
					t.Error("expected all hash findings to have critical severity")
				}
				s = New(&Config{RootPaths: []string{root}, ScanMode: mode, Output: io.Discard, Allowlist: &config.Allowlist{DisableFindingTypes: []string{"malware-hash"}}})
				s.scanHashes()
				if s.report.HasFindings() {
					t.Errorf("disabled hash findings were reported: %+v", s.report.Findings)
				}
			})
		}
	}
}

func writeTensorlakeFixture(t *testing.T, root, relativePath, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
