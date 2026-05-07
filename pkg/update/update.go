// Package update checks GitHub releases and downloads matching update assets.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var errChecksumEntryNotFound = errors.New("checksum entry not found")

const (
	defaultOwner   = "Idox-GenAI"
	defaultRepo    = "shai-hulud-scanner"
	defaultBaseURL = "https://api.github.com"
	userAgent      = "shai-hulud-scanner-update-checker"
)

// Checker performs update checks against GitHub releases.
type Checker struct {
	Owner      string
	Repo       string
	BaseURL    string
	HTTPClient *http.Client
	GOOS       string
	GOARCH     string
	CacheDir   string
	OSRelease  string
}

// Result describes the outcome of an update check.
type Result struct {
	CurrentVersion   string
	LatestVersion    string
	UpdateAvailable  bool
	AssetName        string
	DownloadPath     string
	ChecksumVerified bool
}

type release struct {
	TagName string         `json:"tag_name"`
	Name    string         `json:"name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// NewChecker returns a checker configured for the public project releases.
func NewChecker() *Checker {
	return &Checker{
		Owner:      defaultOwner,
		Repo:       defaultRepo,
		BaseURL:    defaultBaseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		OSRelease:  "/etc/os-release",
	}
}

// CheckAndDownload downloads the matching release asset when latest is newer than currentVersion.
func (c *Checker) CheckAndDownload(ctx context.Context, currentVersion string) (*Result, error) {
	rel, err := c.latestRelease(ctx)
	if err != nil {
		return nil, err
	}

	result, shouldDownload, err := updateResult(rel, currentVersion)
	if err != nil {
		return nil, err
	}
	if !shouldDownload {
		return result, nil
	}

	asset, destPath, err := c.downloadSelectedAsset(ctx, rel)
	if err != nil {
		return nil, err
	}
	result.AssetName = asset.Name
	result.DownloadPath = destPath

	checksumVerified, err := c.verifyChecksumIfAvailable(ctx, rel, destPath)
	if err != nil {
		return nil, err
	}
	result.ChecksumVerified = checksumVerified

	return result, nil
}

func updateResult(rel *release, currentVersion string) (*Result, bool, error) {
	result := &Result{
		CurrentVersion: strings.TrimSpace(currentVersion),
		LatestVersion:  rel.TagName,
	}

	cmp, err := CompareVersions(rel.TagName, currentVersion)
	if err != nil {
		return nil, false, err
	}
	if cmp <= 0 {
		return result, false, nil
	}

	result.UpdateAvailable = true
	return result, true, nil
}

func (c *Checker) latestRelease(ctx context.Context) (*release, error) {
	req, err := c.newGitHubRequest(ctx, c.latestReleaseURL())
	if err != nil {
		return nil, err
	}

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("check latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("check latest release: GitHub returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var rel release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode latest release: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, errors.New("latest release did not include a tag name")
	}
	return &rel, nil
}

func (c *Checker) latestReleaseURL() string {
	baseURL := strings.TrimRight(c.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return fmt.Sprintf("%s/repos/%s/%s/releases/latest", baseURL, c.Owner, c.Repo)
}

func (c *Checker) newGitHubRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func (c *Checker) selectAsset(assets []releaseAsset) (releaseAsset, error) {
	target := c.targetPlatform()
	patterns, err := target.assetPatterns()
	if err != nil {
		return releaseAsset{}, err
	}

	if asset, ok := findAssetMatchingAnyPattern(assets, patterns); ok {
		return asset, nil
	}
	return releaseAsset{}, fmt.Errorf("no update asset found for %s/%s", target.goos, target.goarch)
}

type targetPlatform struct {
	goos        string
	goarch      string
	packageKind string
}

func (c *Checker) targetPlatform() targetPlatform {
	goos := c.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}

	goarch := c.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	target := targetPlatform{
		goos:   goos,
		goarch: goarch,
	}
	if goos == "linux" {
		target.packageKind = c.linuxPackageKind()
	}
	return target
}

func (p targetPlatform) assetPatterns() ([]string, error) {
	switch p.goos {
	case "darwin":
		return []string{"darwin_" + p.goarch + ".pkg", "darwin-" + p.goarch + ".pkg"}, nil
	case "linux":
		return linuxAssetPatterns(p.goarch, p.packageKind), nil
	case "windows":
		return []string{
			"windows_" + p.goarch + ".zip",
			"windows_" + p.goarch + ".exe",
			"windows-" + p.goarch + ".zip",
			"windows-" + p.goarch + ".exe",
		}, nil
	default:
		return nil, fmt.Errorf("updates are not supported for %s/%s", p.goos, p.goarch)
	}
}

func findAssetMatchingAnyPattern(assets []releaseAsset, patterns []string) (releaseAsset, bool) {
	for _, pattern := range patterns {
		for _, asset := range assets {
			if assetMatchesPattern(asset, pattern) {
				return asset, true
			}
		}
	}
	return releaseAsset{}, false
}

func assetMatchesPattern(asset releaseAsset, pattern string) bool {
	name := strings.ToLower(asset.Name)
	return !strings.Contains(name, "checksums") &&
		strings.Contains(name, strings.ToLower(pattern))
}

func linuxAssetPatterns(goarch, packageKind string) []string {
	switch packageKind {
	case "deb":
		return []string{"linux_" + goarch + ".deb", "linux-" + goarch + ".deb"}
	case "rpm":
		return []string{"linux_" + goarch + ".rpm", "linux-" + goarch + ".rpm"}
	case "archlinux":
		return []string{"linux_" + goarch + ".pkg.tar.zst", "linux-" + goarch + ".pkg.tar.zst"}
	default:
		return []string{
			"linux_" + goarch + ".tar.gz",
			"linux_" + goarch + ".tgz",
			"linux-" + goarch + ".tar.gz",
			"linux-" + goarch + ".tgz",
		}
	}
}

func (c *Checker) linuxPackageKind() string {
	data, err := os.ReadFile(c.OSRelease)
	if err != nil {
		return ""
	}
	ids := parseOSReleaseIDs(string(data))
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu", "linuxmint", "pop":
			return "deb"
		case "fedora", "rhel", "centos", "rocky", "almalinux", "opensuse", "suse":
			return "rpm"
		case "arch", "manjaro":
			return "archlinux"
		}
	}
	return ""
}

func parseOSReleaseIDs(data string) []string {
	values := make([]string, 0, 4)
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "ID" && key != "ID_LIKE" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		for _, field := range strings.Fields(value) {
			values = append(values, strings.ToLower(field))
		}
	}
	return values
}

func (c *Checker) downloadDir() (string, error) {
	if c.CacheDir != "" {
		return c.CacheDir, nil
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("determine user cache directory: %w", err)
	}
	return filepath.Join(cacheDir, defaultRepo, "updates"), nil
}

func (c *Checker) downloadSelectedAsset(ctx context.Context, rel *release) (releaseAsset, string, error) {
	asset, err := c.selectAsset(rel.Assets)
	if err != nil {
		return releaseAsset{}, "", err
	}

	destPath, err := c.downloadPath(asset.Name)
	if err != nil {
		return releaseAsset{}, "", err
	}

	if err := c.downloadFile(ctx, asset.BrowserDownloadURL, destPath); err != nil {
		return releaseAsset{}, "", err
	}
	return asset, destPath, nil
}

func (c *Checker) downloadPath(assetName string) (string, error) {
	destDir, err := c.downloadDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("create update cache directory: %w", err)
	}
	return filepath.Join(destDir, assetName), nil
}

func (c *Checker) downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("download update asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download update asset: server returned %s", resp.Status)
	}

	tmpPath := destPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create update asset: %w", err)
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write update asset: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close update asset: %w", closeErr)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save update asset: %w", err)
	}
	return nil
}

func (c *Checker) verifyChecksumIfAvailable(ctx context.Context, rel *release, destPath string) (bool, error) {
	checksum, ok := checksumForAsset(rel.Assets)
	if !ok {
		return false, nil
	}
	if err := c.verifyChecksum(ctx, checksum, destPath); err != nil {
		return false, err
	}
	return true, nil
}

func checksumForAsset(assets []releaseAsset) (releaseAsset, bool) {
	for _, asset := range assets {
		if strings.EqualFold(asset.Name, "checksums.txt") {
			return asset, true
		}
	}
	return releaseAsset{}, false
}

func (c *Checker) verifyChecksum(ctx context.Context, checksumAsset releaseAsset, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumAsset.BrowserDownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download checksums: server returned %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}

	want, ok := checksumFromList(string(data), filepath.Base(destPath))
	if !ok {
		return fmt.Errorf("%w: checksums.txt did not contain %s", errChecksumEntryNotFound, filepath.Base(destPath))
	}
	got, err := fileSHA256(destPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s", filepath.Base(destPath))
	}
	return nil
}

func checksumFromList(data, assetName string) (string, bool) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == assetName {
			return fields[0], true
		}
	}
	return "", false
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open update asset for checksum: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash update asset: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Checker) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

var versionTokenRE = regexp.MustCompile(`\d+|[A-Za-z]+`)

// CompareVersions compares latest and current versions.
// It returns 1 when latest is newer, -1 when current is newer, and 0 when equal.
func CompareVersions(latest, current string) (int, error) {
	l, err := parseVersion(latest)
	if err != nil {
		return 0, fmt.Errorf("parse latest version %q: %w", latest, err)
	}
	c, err := parseVersion(current)
	if err != nil {
		return 0, fmt.Errorf("parse current version %q: %w", current, err)
	}
	for i := 0; i < 3; i++ {
		if l.nums[i] > c.nums[i] {
			return 1, nil
		}
		if l.nums[i] < c.nums[i] {
			return -1, nil
		}
	}
	if l.pre == "" && c.pre != "" {
		return 1, nil
	}
	if l.pre != "" && c.pre == "" {
		return -1, nil
	}
	return comparePrerelease(l.pre, c.pre), nil
}

type parsedVersion struct {
	nums [3]int
	pre  string
}

func parseVersion(value string) (parsedVersion, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "v")
	value = strings.TrimPrefix(value, "V")
	value, _, _ = strings.Cut(value, "+")
	mainPart, pre, _ := strings.Cut(value, "-")
	parts := strings.Split(mainPart, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return parsedVersion{}, errors.New("expected major.minor.patch")
	}
	var parsed parsedVersion
	for i, part := range parts {
		if part == "" {
			return parsedVersion{}, errors.New("empty version component")
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return parsedVersion{}, err
		}
		parsed.nums[i] = n
	}
	parsed.pre = normalizePrerelease(pre)
	return parsed, nil
}

func normalizePrerelease(value string) string {
	if value == "" {
		return ""
	}
	tokens := versionTokenRE.FindAllString(value, -1)
	return strings.ToLower(strings.Join(tokens, "."))
}

func comparePrerelease(latest, current string) int {
	lTokens := strings.Split(latest, ".")
	cTokens := strings.Split(current, ".")
	for i := 0; i < len(lTokens) || i < len(cTokens); i++ {
		if i >= len(lTokens) {
			return -1
		}
		if i >= len(cTokens) {
			return 1
		}

		lNum, lErr := strconv.Atoi(lTokens[i])
		cNum, cErr := strconv.Atoi(cTokens[i])
		if lErr == nil && cErr == nil {
			if lNum > cNum {
				return 1
			}
			if lNum < cNum {
				return -1
			}
			continue
		}
		if lErr == nil {
			return -1
		}
		if cErr == nil {
			return 1
		}
		if cmp := strings.Compare(lTokens[i], cTokens[i]); cmp != 0 {
			return cmp
		}
	}
	return 0
}
