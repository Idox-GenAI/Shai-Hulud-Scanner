package update

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		want    int
	}{
		{name: "latest newer with v prefix", latest: "v1.2.4", current: "1.2.3", want: 1},
		{name: "same version", latest: "1.2.3", current: "v1.2.3", want: 0},
		{name: "current newer", latest: "1.2.3", current: "1.3.0", want: -1},
		{name: "release beats prerelease", latest: "1.2.3", current: "1.2.3-next", want: 1},
		{name: "prerelease older than release", latest: "1.2.3-rc.1", current: "1.2.3", want: -1},
		{name: "numeric prerelease compares numerically", latest: "1.2.3-rc.10", current: "1.2.3-rc.2", want: 1},
		{name: "numeric prerelease sorts before text token", latest: "1.2.3-2", current: "1.2.3-alpha", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareVersions(tt.latest, tt.current)
			if err != nil {
				t.Fatalf("CompareVersions() error = %v", err)
			}
			if normalizeCompare(got) != tt.want {
				t.Fatalf("CompareVersions() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSelectAsset(t *testing.T) {
	assets := []releaseAsset{
		{Name: "checksums.txt"},
		{Name: "shai-hulud-scanner_1.2.4_darwin_arm64.pkg"},
		{Name: "shai-hulud-scanner_1.2.4_linux_amd64.deb"},
		{Name: "shai-hulud-scanner_1.2.4_linux_arm64.rpm"},
		{Name: "shai-hulud-scanner_1.2.4_windows_amd64.zip"},
		{Name: "shai-hulud-scanner_1.2.4_linux_arm64.tar.gz"},
	}

	t.Run("macos pkg", func(t *testing.T) {
		checker := &Checker{GOOS: "darwin", GOARCH: "arm64"}
		asset, err := checker.selectAsset(assets)
		if err != nil {
			t.Fatalf("selectAsset() error = %v", err)
		}
		if asset.Name != "shai-hulud-scanner_1.2.4_darwin_arm64.pkg" {
			t.Fatalf("asset = %q", asset.Name)
		}
	})

	t.Run("debian package", func(t *testing.T) {
		osRelease := writeTempOSRelease(t, `ID=ubuntu`)
		checker := &Checker{GOOS: "linux", GOARCH: "amd64", OSRelease: osRelease}
		asset, err := checker.selectAsset(assets)
		if err != nil {
			t.Fatalf("selectAsset() error = %v", err)
		}
		if asset.Name != "shai-hulud-scanner_1.2.4_linux_amd64.deb" {
			t.Fatalf("asset = %q", asset.Name)
		}
	})

	t.Run("rpm package", func(t *testing.T) {
		osRelease := writeTempOSRelease(t, `ID_LIKE="fedora rhel"`)
		checker := &Checker{GOOS: "linux", GOARCH: "arm64", OSRelease: osRelease}
		asset, err := checker.selectAsset(assets)
		if err != nil {
			t.Fatalf("selectAsset() error = %v", err)
		}
		if asset.Name != "shai-hulud-scanner_1.2.4_linux_arm64.rpm" {
			t.Fatalf("asset = %q", asset.Name)
		}
	})

	t.Run("unknown linux falls back to archive", func(t *testing.T) {
		osRelease := writeTempOSRelease(t, `ID=void`)
		checker := &Checker{GOOS: "linux", GOARCH: "arm64", OSRelease: osRelease}
		asset, err := checker.selectAsset(assets)
		if err != nil {
			t.Fatalf("selectAsset() error = %v", err)
		}
		if asset.Name != "shai-hulud-scanner_1.2.4_linux_arm64.tar.gz" {
			t.Fatalf("asset = %q", asset.Name)
		}
	})

	t.Run("windows archive", func(t *testing.T) {
		checker := &Checker{GOOS: "windows", GOARCH: "amd64"}
		asset, err := checker.selectAsset(assets)
		if err != nil {
			t.Fatalf("selectAsset() error = %v", err)
		}
		if asset.Name != "shai-hulud-scanner_1.2.4_windows_amd64.zip" {
			t.Fatalf("asset = %q", asset.Name)
		}
	})
}

func TestCheckAndDownloadWithChecksum(t *testing.T) {
	const assetName = "shai-hulud-scanner_1.2.4_darwin_arm64.pkg"
	assetBody := []byte("installer package")
	assetSum := sha256.Sum256(assetBody)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			fmt.Fprintf(w, `{
				"tag_name": "v1.2.4",
				"assets": [
					{"name": %q, "browser_download_url": %q},
					{"name": "checksums.txt", "browser_download_url": %q}
				]
			}`, assetName, serverURL+"/download/"+assetName, serverURL+"/download/checksums.txt")
		case "/download/" + assetName:
			_, _ = w.Write(assetBody)
		case "/download/checksums.txt":
			fmt.Fprintf(w, "%x  %s\n", assetSum, assetName)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	cacheDir := t.TempDir()
	checker := &Checker{
		Owner:      "owner",
		Repo:       "repo",
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		GOOS:       "darwin",
		GOARCH:     "arm64",
		CacheDir:   cacheDir,
	}

	result, err := checker.CheckAndDownload(context.Background(), "1.2.3")
	if err != nil {
		t.Fatalf("CheckAndDownload() error = %v", err)
	}
	if !result.UpdateAvailable {
		t.Fatal("expected update to be available")
	}
	if !result.ChecksumVerified {
		t.Fatal("expected checksum verification")
	}
	got, err := os.ReadFile(filepath.Join(cacheDir, assetName))
	if err != nil {
		t.Fatalf("read downloaded asset: %v", err)
	}
	if string(got) != string(assetBody) {
		t.Fatalf("downloaded asset = %q", got)
	}
}

func TestCheckAndDownloadFailsMissingChecksumEntry(t *testing.T) {
	const assetName = "shai-hulud-scanner_v1.2.4_darwin_arm64.pkg"
	assetBody := []byte("installer package")

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			fmt.Fprintf(w, `{
				"tag_name": "v1.2.4",
				"assets": [
					{"name": %q, "browser_download_url": %q},
					{"name": "checksums.txt", "browser_download_url": %q}
				]
			}`, assetName, serverURL+"/download/"+assetName, serverURL+"/download/checksums.txt")
		case "/download/" + assetName:
			_, _ = w.Write(assetBody)
		case "/download/checksums.txt":
			fmt.Fprint(w, "abc123  another-file.tar.gz\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	checker := &Checker{
		Owner:      "owner",
		Repo:       "repo",
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		GOOS:       "darwin",
		GOARCH:     "arm64",
		CacheDir:   t.TempDir(),
	}

	result, err := checker.CheckAndDownload(context.Background(), "1.2.3")
	if err == nil {
		t.Fatal("expected missing checksum entry error")
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil", result)
	}
}

func TestCheckAndDownloadNoUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v1.2.3","assets":[]}`)
	}))
	defer server.Close()

	checker := &Checker{
		Owner:      "owner",
		Repo:       "repo",
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		GOOS:       "darwin",
		GOARCH:     "arm64",
	}
	result, err := checker.CheckAndDownload(context.Background(), "1.2.3")
	if err != nil {
		t.Fatalf("CheckAndDownload() error = %v", err)
	}
	if result.UpdateAvailable {
		t.Fatal("did not expect update")
	}
}

func writeTempOSRelease(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write os-release: %v", err)
	}
	return path
}

func normalizeCompare(value int) int {
	switch {
	case value > 0:
		return 1
	case value < 0:
		return -1
	default:
		return 0
	}
}
