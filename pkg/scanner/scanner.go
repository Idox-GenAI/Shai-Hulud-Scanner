// Package scanner provides the core scanning functionality for Shai-Hulud malware detection.
package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"shai-hulud-scanner/pkg/config"
	"shai-hulud-scanner/pkg/hash"
	"shai-hulud-scanner/pkg/ioc"
	"shai-hulud-scanner/pkg/report"
)

// ScanMode represents the scanning intensity.
type ScanMode string

const (
	ScanModeQuick ScanMode = "quick"
	ScanModeFull  ScanMode = "full"
)

// Config holds the scanner configuration.
type Config struct {
	RootPaths  []string
	ScanMode   ScanMode
	ReportPath string
	NoBanner   bool
	FilesOnly  bool
	CacheFile  string
	Output     io.Writer
	// Strict mode: exit 1 on ANY finding (including warnings)
	Strict bool
	// WarnOnly mode: exit 0 on warnings, only exit 1 on high+ severity
	WarnOnly bool
	// Allowlist configuration for excluding findings
	Allowlist *config.Allowlist
}

// DefaultConfig returns a default scanner configuration.
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	return &Config{
		RootPaths:  []string{homeDir},
		ScanMode:   ScanModeQuick,
		ReportPath: "./ShaiHulud-Scan-Report.txt",
		NoBanner:   false,
		FilesOnly:  false,
		CacheFile:  filepath.Join(os.TempDir(), "compromised-packages-cache.txt"),
		Output:     os.Stdout,
	}
}

// Scanner performs malware detection scans.
type Scanner struct {
	config           *Config
	report           *report.Report
	compromisedPkgs  map[string]bool            // unscoped packages
	compromisedScope map[string]map[string]bool // scoped packages: scope -> name -> true
	compromisedAny   map[string]bool            // full package name -> any version
	compromisedVer   map[string]map[string]bool // full package name -> exact versions
	scopes           map[string]bool
	allowlist        *config.Allowlist
	mu               sync.Mutex // protects report during parallel scans
}

// New creates a new Scanner with the given configuration.
func New(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Scanner{
		config:           cfg,
		report:           report.NewReport(string(cfg.ScanMode), cfg.RootPaths),
		compromisedPkgs:  make(map[string]bool),
		compromisedScope: make(map[string]map[string]bool),
		compromisedAny:   make(map[string]bool),
		compromisedVer:   make(map[string]map[string]bool),
		scopes:           make(map[string]bool),
		allowlist:        cfg.Allowlist,
	}
}

// shouldSkipFinding checks if a finding should be skipped based on the allowlist.
func (s *Scanner) shouldSkipFinding(ft report.FindingType, indicator, location string) bool {
	if s.allowlist == nil {
		return false
	}
	return s.allowlist.ShouldSkipFinding(ft, indicator, location)
}

// addFinding adds a finding to the report if not excluded by allowlist.
// This method is thread-safe for use in parallel scans.
func (s *Scanner) addFinding(ft report.FindingType, indicator, location string) {
	if s.shouldSkipFinding(ft, indicator, location) {
		s.log("[*] Skipped (allowlisted): %s - %s", ft, indicator)
		return
	}
	s.mu.Lock()
	s.report.AddFinding(ft, indicator, location)
	s.mu.Unlock()
}

// Run executes the full scan and returns the report.
func (s *Scanner) Run() (*report.Report, error) {
	startTime := time.Now()

	s.logSection("Loading compromised package lists")
	if err := s.loadCompromisedPackages(); err != nil {
		s.log("[!] Error loading compromised packages: %v", err)
	}
	totalPkgs := len(s.compromisedPkgs) + s.countScopedPackages()
	s.report.SetCompromisedPackageCount(totalPkgs)
	if totalPkgs == 0 {
		s.log("[!] No compromised packages loaded. Package-based checks will be limited.")
	} else {
		s.log("[*] Total unique compromised package identifiers loaded: %d", totalPkgs)
	}

	s.logSection("Finding node_modules directories")
	nmDirs := s.findNodeModules()
	s.log("[*] Found %d node_modules directories.", len(nmDirs))

	s.logSection("Scanning for malicious packages in node_modules")
	if len(nmDirs) > 0 && totalPkgs > 0 {
		s.scanNodeModules(nmDirs)
	} else {
		s.log("[-] Skipping node_modules package scan (no packages or dirs).")
	}

	if s.config.ScanMode == ScanModeFull && !s.config.FilesOnly {
		s.logSection("Scanning npm cache for compromised packages")
		npmCache := s.getNpmCachePath()
		if npmCache != "" {
			s.scanNpmCache(npmCache)
		} else {
			s.log("[-] Skipping npm cache scan (no cache path).")
		}
	} else if s.config.ScanMode == ScanModeQuick {
		s.log("[Quick] Skipping npm cache scan (use --mode full)")
	}

	// Run parallel scans for file-based checks
	var wg sync.WaitGroup

	s.logSection("Scanning for known Shai-Hulud artifact files")
	wg.Go(func() {
		s.scanMaliciousFiles()
	})

	s.logSection("Checking for TruffleHog installation")
	wg.Go(func() {
		s.scanTrufflehog()
	})

	if !s.config.FilesOnly {
		s.logSection("Scanning for suspicious git branches and remotes")
		wg.Go(func() {
			s.scanGit()
		})

		s.logSection("Scanning GitHub Actions workflows")
		wg.Go(func() {
			s.scanWorkflows()
		})

		s.logSection("Checking cloud credential files")
		wg.Go(func() {
			s.scanCredentials()
		})

		s.logSection("Scanning postinstall hooks")
		wg.Go(func() {
			s.scanHooks()
		})

		s.logSection("Hash-based malware detection")
		wg.Go(func() {
			s.scanHashes()
		})

		s.logSection("Scanning lockfiles for compromised packages")
		wg.Go(func() {
			s.scanLockfiles()
		})

		s.logSection("Scanning for compromised namespaces")
		wg.Go(func() {
			s.scanCompromisedNamespaces()
		})

		if s.config.ScanMode == ScanModeFull {
			s.logSection("Checking for self-hosted runners")
			wg.Go(func() {
				s.scanRunners()
			})

			s.logSection("Checking for migration suffix attack")
			wg.Go(func() {
				s.scanMigrationSuffix()
			})
		} else {
			s.log("[Quick] Skipping self-hosted runner scan (use --mode full)")
			s.log("[Quick] Skipping migration suffix scan (use --mode full)")
		}
	}

	if s.config.ScanMode == ScanModeFull {
		s.logSection("Scanning for suspicious env+exfil patterns")
		wg.Go(func() {
			s.scanEnvPatterns()
		})
	} else {
		s.log("[Quick] Skipping env+exfil pattern scan (use --mode full)")
	}

	// Wait for all parallel scans to complete
	wg.Wait()

	s.report.SetDuration(time.Since(startTime))
	return s.report, nil
}

func (s *Scanner) log(format string, args ...any) {
	s.mu.Lock()
	fmt.Fprintf(s.config.Output, format+"\n", args...)
	s.mu.Unlock()
}

func (s *Scanner) logSection(title string) {
	s.mu.Lock()
	fmt.Fprintf(s.config.Output, "\n---- %s ----\n", title)
	s.mu.Unlock()
}

func (s *Scanner) countScopedPackages() int {
	count := 0
	for _, pkgs := range s.compromisedScope {
		count += len(pkgs)
	}
	return count
}

func (s *Scanner) loadCompromisedPackages() error {
	var allPackages []string

	// Prefer a fresh cache (<24h old) when available to avoid unnecessary
	// network requests and keep behavior predictable in offline scenarios.
	usedFreshCache := false
	if s.config.CacheFile != "" {
		if info, err := os.Stat(s.config.CacheFile); err == nil {
			age := time.Since(info.ModTime())
			if age < 24*time.Hour {
				s.log("[*] Using cached compromised package snapshot (fresh, <24h): %s", s.config.CacheFile)
				pkgs, err := s.loadCacheFile()
				if err != nil {
					s.log("[!] Failed to load cache file %s: %v", s.config.CacheFile, err)
				} else {
					allPackages = pkgs
					usedFreshCache = true
				}
			} else {
				s.log("[*] Cache file is stale (age: %s); fetching latest compromised package list", age.Round(time.Minute))
			}
		}
	}

	if !usedFreshCache {
		for _, url := range ioc.PackageFeedURLs {
			s.log("[*] Fetching compromised package list from: %s", url)
			pkgs, err := s.fetchPackageList(url)
			if err != nil {
				s.log("[!] Failed to fetch %s: %v", url, err)
				continue
			}
			allPackages = append(allPackages, pkgs...)
		}

		if len(allPackages) == 0 && s.config.CacheFile != "" {
			s.log("[*] Using cached compromised package snapshot: %s", s.config.CacheFile)
			pkgs, err := s.loadCacheFile()
			if err == nil {
				allPackages = pkgs
			}
		}

		// Save to cache whenever we have any packages (from feeds or cache
		// fallback). This keeps the cache file up-to-date and refreshes its
		// modification time when we successfully load data. Cache write errors
		// are logged but do not fail the scan.
		if len(allPackages) > 0 && s.config.CacheFile != "" {
			if err := s.saveCacheFile(allPackages); err != nil {
				s.log("[!] Failed to save cache file %s: %v", s.config.CacheFile, err)
			}
		}
	}

	// Parse package identifiers and optional exact-version constraints.
	for _, raw := range allPackages {
		token := compromisedPackageToken(raw)
		if token == "" {
			continue
		}
		s.addCompromisedPackage(token, compromisedPackageVersions(raw, token))
	}

	return nil
}

// compromisedPackageToken extracts the package identifier from a feed/cache line.
// Feeds are not consistent: some are plain package names, while others are CSV
// rows like "Package,Version" or "@scope/name,= 1.2.3".
func compromisedPackageToken(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	// Prefer the first CSV field when present so scoped packages and package
	// names with descriptions/versions are parsed correctly.
	if firstField, rest, ok := strings.Cut(line, ","); ok {
		firstField = strings.TrimSpace(firstField)
		rest = strings.TrimSpace(rest)
		if strings.EqualFold(firstField, "package") && strings.EqualFold(rest, "version") {
			return ""
		}
		line = firstField
	} else {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return ""
		}
		line = fields[0]
	}

	token := strings.Trim(strings.TrimSpace(line), ",;|")
	if strings.EqualFold(token, "package") {
		return ""
	}
	return token
}

// compromisedPackageVersions extracts exact versions from a CSV-style feed row
// (for example, "name,= 1.2.3 || = 1.2.4"). It returns nil for plain package
// feeds or rows without usable exact versions.
func compromisedPackageVersions(line, token string) []string {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, ",") {
		return nil
	}

	firstField, rest, ok := strings.Cut(line, ",")
	if !ok {
		return nil
	}
	firstField = strings.TrimSpace(firstField)
	rest = strings.TrimSpace(rest)
	if strings.EqualFold(firstField, "package") && strings.EqualFold(rest, "version") {
		return nil
	}
	if !strings.EqualFold(firstField, token) {
		return nil
	}

	versionSpec, _, _ := strings.Cut(rest, ",")
	versionSpec = strings.TrimSpace(versionSpec)
	if versionSpec == "" {
		return nil
	}

	var versions []string
	for part := range strings.SplitSeq(versionSpec, "||") {
		v := normalizePackageVersion(part)
		if !looksLikeExactPackageVersion(v) {
			continue
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return nil
	}
	return versions
}

func looksLikeExactPackageVersion(v string) bool {
	if v == "" {
		return false
	}
	hasDigit := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '.', r == '-', r == '+', r == '_':
		default:
			return false
		}
	}
	return hasDigit
}

func normalizePackageVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "=") {
		v = strings.TrimSpace(strings.TrimPrefix(v, "="))
	}
	if idx := strings.Index(v, "("); idx > 0 {
		v = v[:idx]
	}
	return v
}

func (s *Scanner) addCompromisedPackage(pkgName string, versions []string) {
	if pkgName == "" {
		return
	}

	if strings.HasPrefix(pkgName, "@") && strings.Contains(pkgName, "/") {
		parts := strings.SplitN(pkgName, "/", 2)
		scope := parts[0]
		name := parts[1]
		if s.compromisedScope[scope] == nil {
			s.compromisedScope[scope] = make(map[string]bool)
		}
		s.compromisedScope[scope][name] = true
		s.scopes[scope] = true
	} else {
		s.compromisedPkgs[pkgName] = true
	}

	if len(versions) == 0 {
		s.compromisedAny[pkgName] = true
		return
	}

	if s.compromisedVer[pkgName] == nil {
		s.compromisedVer[pkgName] = make(map[string]bool)
	}
	for _, v := range versions {
		nv := normalizePackageVersion(v)
		if nv == "" {
			continue
		}
		s.compromisedVer[pkgName][nv] = true
	}
}

func (s *Scanner) isCompromisedPackageNoVersion(pkgName string) bool {
	return s.compromisedAny[pkgName]
}

func (s *Scanner) isCompromisedPackageVersion(pkgName, version string) bool {
	if s.compromisedAny[pkgName] {
		return true
	}
	version = normalizePackageVersion(version)
	if version == "" {
		return false
	}
	if versions := s.compromisedVer[pkgName]; versions != nil {
		return versions[version]
	}
	return false
}

func (s *Scanner) fetchPackageList(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var packages []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			packages = append(packages, line)
		}
	}
	return packages, scanner.Err()
}

func (s *Scanner) loadCacheFile() ([]string, error) {
	f, err := os.Open(s.config.CacheFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var packages []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			packages = append(packages, line)
		}
	}
	return packages, scanner.Err()
}

func (s *Scanner) saveCacheFile(packages []string) error {
	if dir := filepath.Dir(s.config.CacheFile); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(s.config.CacheFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, pkg := range packages {
		if _, err := fmt.Fprintln(f, pkg); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) findNodeModules() []string {
	var dirs []string
	seen := make(map[string]bool)

	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			s.log("[!] Root path not found: %s", root)
			continue
		}

		if s.config.ScanMode == ScanModeQuick {
			// Quick mode: only check root and immediate subdirectories
			nmPath := filepath.Join(root, "node_modules")
			if info, err := os.Stat(nmPath); err == nil && info.IsDir() {
				if !seen[nmPath] {
					dirs = append(dirs, nmPath)
					seen[nmPath] = true
				}
			}
			entries, err := os.ReadDir(root)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						subNM := filepath.Join(root, entry.Name(), "node_modules")
						if info, err := os.Stat(subNM); err == nil && info.IsDir() {
							if !seen[subNM] {
								dirs = append(dirs, subNM)
								seen[subNM] = true
							}
						}
					}
				}
			}
		} else {
			// Full mode: recursive search
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() && d.Name() == "node_modules" {
					if !seen[path] {
						dirs = append(dirs, path)
						seen[path] = true
					}
					return filepath.SkipDir
				}
				return nil
			})
		}
	}

	return dirs
}

func (s *Scanner) scanNodeModules(nmDirs []string) {
	for _, nm := range nmDirs {
		entries, err := os.ReadDir(nm)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			name := entry.Name()
			childPath := filepath.Join(nm, name)

			if strings.HasPrefix(name, "@") {
				// Scoped package
				if !s.scopes[name] {
					continue
				}
				subEntries, err := os.ReadDir(childPath)
				if err != nil {
					continue
				}
				for _, subEntry := range subEntries {
					if !subEntry.IsDir() {
						continue
					}
					pkgName := subEntry.Name()
					if s.compromisedScope[name] != nil && s.compromisedScope[name][pkgName] {
						fullName := name + "/" + pkgName
						pkgDir := filepath.Join(childPath, pkgName)
						if s.isCompromisedPackageVersion(fullName, s.readPackageVersion(pkgDir)) {
							s.addFinding(report.FindingNodeModules, fullName, pkgDir)
							s.log("    [!] FOUND: %s at %s", fullName, nm)
						}
					}
				}
			} else {
				// Unscoped package
				if s.compromisedPkgs[name] && s.isCompromisedPackageVersion(name, s.readPackageVersion(childPath)) {
					s.addFinding(report.FindingNodeModules, name, childPath)
					s.log("    [!] FOUND: %s at %s", name, nm)
				}
			}
		}
	}
}

func (s *Scanner) getNpmCachePath() string {
	// Try npm config
	cmd := exec.Command("npm", "config", "get", "cache")
	output, err := cmd.Output()
	if err == nil {
		cachePath := strings.TrimSpace(string(output))
		if cachePath != "" && cachePath != "undefined" {
			if _, err := os.Stat(cachePath); err == nil {
				return cachePath
			}
		}
	}

	// Platform-specific defaults
	homeDir, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(homeDir, "AppData", "Roaming", "npm-cache")
	case "darwin":
		return filepath.Join(homeDir, ".npm")
	default:
		return filepath.Join(homeDir, ".npm")
	}
}

func (s *Scanner) scanNpmCache(cachePath string) {
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		s.log("[*] npm cache path not detected.")
		return
	}

	s.log("[*] Scanning npm cache at: %s", cachePath)

	filepath.WalkDir(cachePath, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}

		name := d.Name()
		// npm cache directory names do not reliably expose package versions, so
		// only version-agnostic feed entries can be matched here.
		if s.compromisedPkgs[name] && s.isCompromisedPackageNoVersion(name) {
			s.addFinding(report.FindingNpmCache, name, path)
			s.log("    [!] FOUND in cache: %s", name)
			return filepath.SkipDir
		}
		// Check scoped
		if strings.HasPrefix(name, "@") && s.scopes[name] {
			// Check subdirectories for package names
			subEntries, _ := os.ReadDir(path)
			for _, sub := range subEntries {
				if sub.IsDir() && s.compromisedScope[name] != nil && s.compromisedScope[name][sub.Name()] {
					fullName := name + "/" + sub.Name()
					if s.isCompromisedPackageNoVersion(fullName) {
						s.addFinding(report.FindingNpmCache, fullName, filepath.Join(path, sub.Name()))
						s.log("    [!] FOUND in cache: %s", fullName)
					}
				}
			}
		}
		return nil
	})
}

func (s *Scanner) scanMaliciousFiles() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		for _, fpath := range ioc.MaliciousFilePaths {
			if !pathWithinRoot(fpath, root) {
				continue
			}
			if _, err := os.Stat(fpath); err == nil {
				s.addFinding(report.FindingFileArtifact, fpath, fpath)
				s.log("    [!] FOUND: %s", fpath)
			}
		}

		if s.config.ScanMode == ScanModeQuick {
			// Quick mode: check root and .github/workflows only
			for _, fname := range ioc.MaliciousFileNames {
				fpath := filepath.Join(root, fname)
				if _, err := os.Stat(fpath); err == nil {
					s.addFinding(report.FindingFileArtifact, fname, fpath)
					s.log("    [!] FOUND: %s at %s", fname, root)
				}

				wfPath := filepath.Join(root, ".github", "workflows", fname)
				if _, err := os.Stat(wfPath); err == nil {
					s.addFinding(report.FindingFileArtifact, fname, wfPath)
					s.log("    [!] FOUND: %s at %s", fname, filepath.Join(root, ".github", "workflows"))
				}
			}
		} else {
			// Full mode: recursive search
			malNames := make(map[string]bool)
			for _, n := range ioc.MaliciousFileNames {
				malNames[n] = true
			}

			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if malNames[d.Name()] {
					s.addFinding(report.FindingFileArtifact, d.Name(), path)
					s.log("    [!] FOUND: %s at %s", d.Name(), filepath.Dir(path))
				}
				return nil
			})
		}
	}
}

func pathWithinRoot(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func (s *Scanner) scanGit() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		var gitDirs []string

		if s.config.ScanMode == ScanModeQuick {
			// Quick mode: check root and immediate subdirectories
			gitPath := filepath.Join(root, ".git")
			if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
				gitDirs = append(gitDirs, gitPath)
			}
			entries, _ := os.ReadDir(root)
			count := 0
			for _, entry := range entries {
				if count >= 20 {
					break
				}
				if entry.IsDir() {
					subGit := filepath.Join(root, entry.Name(), ".git")
					if info, err := os.Stat(subGit); err == nil && info.IsDir() {
						gitDirs = append(gitDirs, subGit)
					}
				}
				count++
			}
		} else {
			// Full mode: recursive search
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() && d.Name() == ".git" {
					gitDirs = append(gitDirs, path)
					return filepath.SkipDir
				}
				return nil
			})
		}

		for _, gitDir := range gitDirs {
			repoDir := filepath.Dir(gitDir)
			s.checkGitRepo(repoDir)
		}
	}
}

func (s *Scanner) checkGitRepo(repoDir string) {
	// Check branches
	cmd := exec.Command("git", "-C", repoDir, "branch", "-a")
	output, err := cmd.Output()
	if err == nil {
		branches := string(output)
		for line := range strings.SplitSeq(branches, "\n") {
			branch := strings.TrimSpace(line)
			branch = strings.TrimPrefix(branch, "* ")
			if ioc.ContainsSuspiciousBranchPattern(branch) {
				s.addFinding(report.FindingGitBranch, "Branch: "+branch, repoDir)
			}
		}
	}

	// Check remotes
	cmd = exec.Command("git", "-C", repoDir, "remote", "-v")
	output, err = cmd.Output()
	if err == nil {
		remotes := string(output)
		if strings.Contains(strings.ToLower(remotes), "shai-hulud") {
			s.addFinding(report.FindingGitRemote, "Remote contains 'Shai-Hulud'", repoDir)
		}
	}
}

func (s *Scanner) scanWorkflows() {
	formatterRegex := regexp.MustCompile(`^formatter_\d+\.yml$`)

	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && strings.HasSuffix(path, filepath.Join(".github", "workflows")) {
				// Scan workflow files in this directory
				wfEntries, _ := os.ReadDir(path)
				for _, wf := range wfEntries {
					if wf.IsDir() {
						continue
					}
					name := wf.Name()
					if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
						continue
					}

					wfPath := filepath.Join(path, name)

					// Check for suspicious workflow name patterns
					if formatterRegex.MatchString(name) {
						s.addFinding(report.FindingWorkflowPattern, "Suspicious workflow name: "+name, wfPath)
						s.log("    [!] SUSPICIOUS workflow: %s", wfPath)
					}

					// Check workflow content
					content, err := os.ReadFile(wfPath)
					if err != nil {
						continue
					}
					if pattern, found := ioc.ContainsSuspiciousWorkflowPattern(string(content)); found {
						s.addFinding(report.FindingWorkflowContent, "Workflow contains: "+pattern, wfPath)
					}
				}
				return filepath.SkipDir
			}
			return nil
		})
	}
}

func (s *Scanner) scanCredentials() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		for _, credPath := range ioc.CloudCredentialPaths {
			if credPath == ".env" {
				continue
			}
			fullPath := filepath.Join(root, credPath)
			if _, err := os.Stat(fullPath); err == nil {
				s.addFinding(report.FindingCredentialFile, credPath, fullPath)
			}
		}

		if s.config.ScanMode == ScanModeFull {
			// Find all .env* files
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip node_modules
				if pathHasDirSegment(path, "node_modules") {
					return nil
				}
				if strings.HasPrefix(d.Name(), ".env") {
					s.addFinding(report.FindingCredentialFile, ".env file", path)
				}
				return nil
			})
		} else {
			// Quick mode: just check root .env
			envPath := filepath.Join(root, ".env")
			if _, err := os.Stat(envPath); err == nil {
				s.addFinding(report.FindingCredentialFile, ".env file", envPath)
			}
		}
	}
}

func (s *Scanner) scanRunners() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}

			name := d.Name()
			isRunnerDir := false
			for _, pattern := range ioc.RunnerDirPatterns {
				if name == pattern || strings.Contains(name, "runner") {
					isRunnerDir = true
					break
				}
			}

			if !isRunnerDir {
				return nil
			}

			runnerFile := filepath.Join(path, ".runner")
			if _, err := os.Stat(runnerFile); err == nil {
				content, err := os.ReadFile(runnerFile)
				if err == nil && strings.Contains(string(content), "SHA1HULUD") {
					s.addFinding(report.FindingMaliciousRunner, "Malicious self-hosted runner 'SHA1HULUD'", path)
					s.log("    [!] CRITICAL: Malicious runner at %s", path)
				} else {
					s.addFinding(report.FindingRunnerInstallation, "Self-hosted runner installation (verify legitimacy)", path)
				}
			}

			return nil
		})
	}
}

func (s *Scanner) scanHooks() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		if s.config.ScanMode == ScanModeQuick {
			// Quick mode: only check root package.json
			pkgPath := filepath.Join(root, "package.json")
			s.checkPackageJson(pkgPath)
		} else {
			// Full mode: find all package.json files
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip deeply nested node_modules
				if pathDirSegmentCount(path, "node_modules") > 1 {
					return nil
				}
				if d.Name() == "package.json" {
					s.checkPackageJson(path)
				}
				return nil
			})
		}
	}
}

func (s *Scanner) checkPackageJson(pkgPath string) {
	if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
		return
	}

	content, err := os.ReadFile(pkgPath)
	if err != nil {
		return
	}

	var pkg struct {
		Scripts              map[string]string `json:"scripts"`
		Dependencies         json.RawMessage   `json:"dependencies"`
		DevDependencies      json.RawMessage   `json:"devDependencies"`
		OptionalDependencies json.RawMessage   `json:"optionalDependencies"`
		PeerDependencies     json.RawMessage   `json:"peerDependencies"`
		BundledDependencies  json.RawMessage   `json:"bundledDependencies"`
		BundleDependencies   json.RawMessage   `json:"bundleDependencies"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return
	}

	for _, hookName := range ioc.HookNames {
		script, ok := pkg.Scripts[hookName]
		if !ok {
			continue
		}
		if pattern, found := ioc.ContainsSuspiciousHookPattern(script); found {
			s.addFinding(report.FindingPostinstallHook, fmt.Sprintf("Suspicious %s: %s", hookName, pattern), pkgPath)
		}
	}

	s.checkPackageJSONDependencies(pkgPath, "dependencies", packageJSONDependencyMap(pkg.Dependencies))
	s.checkPackageJSONDependencies(pkgPath, "devDependencies", packageJSONDependencyMap(pkg.DevDependencies))
	s.checkPackageJSONDependencies(pkgPath, "optionalDependencies", packageJSONDependencyMap(pkg.OptionalDependencies))
	s.checkPackageJSONDependencies(pkgPath, "peerDependencies", packageJSONDependencyMap(pkg.PeerDependencies))
	s.checkPackageJSONBundledDependencies(pkgPath, "bundledDependencies", packageJSONDependencyList(pkg.BundledDependencies))
	s.checkPackageJSONBundledDependencies(pkgPath, "bundleDependencies", packageJSONDependencyList(pkg.BundleDependencies))
}

func packageJSONDependencyMap(raw json.RawMessage) map[string]string {
	var deps map[string]string
	if len(raw) == 0 || json.Unmarshal(raw, &deps) != nil {
		return nil
	}
	return deps
}

func packageJSONDependencyList(raw json.RawMessage) []string {
	var deps []string
	if len(raw) == 0 || json.Unmarshal(raw, &deps) != nil {
		return nil
	}
	return deps
}

func (s *Scanner) checkPackageJSONDependencies(pkgPath, section string, deps map[string]string) {
	for pkgName, spec := range deps {
		if !s.isCompromisedManifestDependency(pkgName, spec) {
			continue
		}
		s.addFinding(report.FindingPackageJSONComp,
			fmt.Sprintf("package.json %s declares compromised package: %s@%s", section, pkgName, spec),
			pkgPath)
		s.log("    [!] PACKAGE.JSON: Compromised package %s in %s", pkgName, pkgPath)
	}
}

func (s *Scanner) checkPackageJSONBundledDependencies(pkgPath, section string, deps []string) {
	for _, pkgName := range deps {
		pkgName = strings.TrimSpace(pkgName)
		if pkgName == "" || !s.isCompromisedPackageNoVersion(pkgName) {
			continue
		}
		s.addFinding(report.FindingPackageJSONComp,
			fmt.Sprintf("package.json %s declares compromised package: %s", section, pkgName),
			pkgPath)
		s.log("    [!] PACKAGE.JSON: Compromised package %s in %s", pkgName, pkgPath)
	}
}

func (s *Scanner) isCompromisedManifestDependency(pkgName, spec string) bool {
	if s.isCompromisedPackageNoVersion(pkgName) {
		return true
	}
	version := exactManifestVersion(spec)
	return version != "" && s.isCompromisedPackageVersion(pkgName, version)
}

func exactManifestVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if strings.HasPrefix(spec, "=") {
		spec = strings.TrimSpace(strings.TrimPrefix(spec, "="))
	}
	if !looksLikeExactPackageVersion(spec) {
		return ""
	}
	return normalizePackageVersion(spec)
}

func (s *Scanner) scanHashes() {
	suspiciousNames := make(map[string]bool)
	for _, n := range ioc.SuspiciousFileNames {
		suspiciousNames[n] = true
	}

	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		if s.config.ScanMode == ScanModeQuick {
			// Quick mode: only check files with suspicious names
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip deeply nested node_modules
				if pathDirSegmentCount(path, "node_modules") > 1 {
					return nil
				}
				if suspiciousNames[d.Name()] {
					s.checkFileHash(path)
				}
				return nil
			})
		} else {
			// Full mode: check all .js and .ts files
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Full mode scans node_modules too; payloads are often installed dependencies.
				name := d.Name()
				if strings.HasSuffix(name, ".d.ts") {
					return nil
				}
				if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") {
					s.checkFileHash(path)
				}
				return nil
			})
		}
	}
}

func (s *Scanner) checkFileHash(filePath string) {
	sha256Hash, sha1Hash, err := hash.ComputeBothHashes(filePath)
	if err != nil {
		return
	}

	if desc, found := ioc.IsMaliciousSHA256(sha256Hash); found {
		s.addFinding(report.FindingMalwareHash, "SHA256 match: "+desc, filePath)
		s.log("    [!!!] MALWARE DETECTED: %s", filePath)
		return
	}

	if desc, found := ioc.IsMaliciousSHA1(sha1Hash); found {
		s.addFinding(report.FindingMalwareHash, "SHA1 match: "+desc, filePath)
		s.log("    [!!!] MALWARE DETECTED: %s", filePath)
	}
}

func (s *Scanner) scanMigrationSuffix() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}

			// Check for -migration directories
			if strings.HasSuffix(d.Name(), "-migration") {
				s.addFinding(report.FindingMigrationAttack, "Directory ends with -migration", path)
			}

			// Check git remotes for -migration
			if d.Name() == ".git" {
				repoDir := filepath.Dir(path)
				cmd := exec.Command("git", "-C", repoDir, "remote", "-v")
				output, err := cmd.Output()
				if err == nil && strings.Contains(strings.ToLower(string(output)), "-migration") {
					s.addFinding(report.FindingMigrationAttack, "Remote URL contains '-migration'", repoDir)
				}
				return filepath.SkipDir
			}

			return nil
		})
	}
}

func (s *Scanner) scanTrufflehog() {
	// Check if trufflehog is in PATH
	if path, err := exec.LookPath("trufflehog"); err == nil {
		s.addFinding(report.FindingTrufflehog, "TruffleHog in PATH", path)
	}

	if s.config.ScanMode == ScanModeFull {
		for _, root := range s.config.RootPaths {
			if _, err := os.Stat(root); os.IsNotExist(err) {
				continue
			}

			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}

				name := d.Name()
				// Check for trufflehog binary
				if name == "trufflehog" || name == "trufflehog.exe" {
					s.addFinding(report.FindingTrufflehog, "TruffleHog binary", path)
				}

				// Check package.json for trufflehog references
				if name == "package.json" && pathDirSegmentCount(path, "node_modules") < 2 {
					content, err := os.ReadFile(path)
					if err == nil && strings.Contains(strings.ToLower(string(content)), "trufflehog") {
						s.addFinding(report.FindingTrufflehogRef, "package.json references trufflehog", path)
					}
				}

				return nil
			})
		}
	}
}

func (s *Scanner) scanEnvPatterns() {
	codeExtensions := map[string]bool{
		".js":  true,
		".ts":  true,
		".py":  true,
		".sh":  true,
		".ps1": true,
	}

	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			// Skip node_modules and .d.ts
			if pathHasDirSegment(path, "node_modules") {
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, ".d.ts") {
				return nil
			}

			ext := filepath.Ext(name)
			if !codeExtensions[ext] {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			contentStr := string(content)
			lowerContent := strings.ToLower(contentStr)
			hasEnvAccess := false
			hasExfil := false

			for _, pattern := range ioc.EnvAccessPatterns {
				if strings.Contains(lowerContent, strings.ToLower(pattern)) {
					hasEnvAccess = true
					break
				}
			}

			for _, pattern := range ioc.ExfilPatterns {
				if strings.Contains(lowerContent, strings.ToLower(pattern)) {
					hasExfil = true
					break
				}
			}

			if hasEnvAccess && hasExfil {
				s.addFinding(report.FindingEnvExfil, "Env access + exfil pattern", path)
				s.log("    [!] SUSPICIOUS env+exfil: %s", path)
			}

			return nil
		})
	}
}

// scanCompromisedNamespaces scans package.json files for dependencies from compromised namespaces.
func (s *Scanner) scanCompromisedNamespaces() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			// Skip node_modules (we scan those separately)
			if pathHasDirSegment(path, "node_modules") {
				return nil
			}

			if d.Name() != "package.json" {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			contentStr := string(content)
			for _, ns := range ioc.CompromisedNamespaces {
				// Check if the namespace appears in the package.json
				if strings.Contains(contentStr, "\""+ns+"/") {
					s.addFinding(report.FindingCompromisedNS,
						fmt.Sprintf("Package from compromised namespace: %s", ns),
						path)
					s.log("    [!] COMPROMISED NAMESPACE: %s in %s", ns, path)
				}
			}

			return nil
		})
	}
}

// scanLockfiles scans lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml) for
// compromised package versions.
func (s *Scanner) scanLockfiles() {
	for _, root := range s.config.RootPaths {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			// Skip node_modules
			if pathHasDirSegment(path, "node_modules") {
				return nil
			}

			name := d.Name()
			switch name {
			case "package-lock.json":
				s.scanPackageLockJSON(path)
			case "yarn.lock":
				s.scanYarnLock(path)
			case "pnpm-lock.yaml":
				s.scanPnpmLock(path)
			}

			return nil
		})
	}
}

// scanPackageLockJSON scans a package-lock.json file for compromised packages.
func (s *Scanner) scanPackageLockJSON(lockPath string) {
	content, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}

	var lockfile struct {
		Packages     map[string]json.RawMessage `json:"packages"`
		Dependencies map[string]packageLockDep  `json:"dependencies"`
	}

	if err := json.Unmarshal(content, &lockfile); err != nil {
		return
	}

	// Modern format (npm v7+): packages field
	for pkgPath := range lockfile.Packages {
		if pkgPath == "" {
			continue
		}
		pkgName := packageNameFromPackageLockPath(pkgPath)
		if pkgName == "" {
			continue
		}
		var pkgMeta struct {
			Version string `json:"version"`
		}
		_ = json.Unmarshal(lockfile.Packages[pkgPath], &pkgMeta)
		s.addLockfileFindingIfCompromised(pkgName, pkgMeta.Version, lockPath)
	}

	// Legacy format (npm v6): dependencies field
	s.scanLegacyPackageLockDependencies(lockfile.Dependencies, lockPath)
}

// scanYarnLock scans a yarn.lock file for compromised packages.
func (s *Scanner) scanYarnLock(lockPath string) {
	content, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}

	// yarn.lock entries are block-based. The key line holds selectors (often
	// version ranges), while the resolved package version appears on a later
	// `version "x.y.z"` line. We use the resolved version for matching.
	lines := strings.SplitSeq(string(content), "\n")
	var currentPackages []string
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasSuffix(line, ":") {
			currentPackages = parseYarnLockHeaderPackages(strings.Trim(line, "\":"))
			continue
		}
		if len(currentPackages) == 0 || !strings.HasPrefix(line, "version ") {
			continue
		}

		version := strings.TrimSpace(strings.TrimPrefix(line, "version "))
		version = strings.Trim(version, "\"")
		for _, pkgName := range currentPackages {
			s.addLockfileFindingIfCompromised(pkgName, version, lockPath)
		}
		// One resolved version line per block.
		currentPackages = nil
	}
}

// scanPnpmLock scans a pnpm-lock.yaml file for compromised packages.
func (s *Scanner) scanPnpmLock(lockPath string) {
	content, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}

	// pnpm-lock.yaml is YAML. We do a simple text-based scan for package names
	// since full YAML parsing would require an external dependency.
	// Packages appear as keys like: /@scope/name@version: or /name@version:
	lines := strings.SplitSeq(string(content), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for package entries (start with / and contain @version)
		if !strings.HasPrefix(line, "/") {
			continue
		}

		// Format: /@scope/name@version: or /name@version:
		line = strings.TrimPrefix(line, "/")
		line = strings.TrimSuffix(line, ":")

		var pkgName string
		if strings.HasPrefix(line, "@") {
			// Scoped: @scope/name@version
			parts := strings.SplitN(line, "@", 3)
			if len(parts) >= 2 {
				pkgName = "@" + parts[1]
			}
		} else {
			// Unscoped: name@version
			parts := strings.SplitN(line, "@", 2)
			if len(parts) >= 1 {
				pkgName = parts[0]
			}
		}

		if pkgName == "" {
			continue
		}

		s.addLockfileFindingIfCompromised(pkgName, versionFromLockKey(line, pkgName), lockPath)
	}
}

// packageLockDep models the subset of npm v6 lockfile dependency entries we
// need so nested transitive dependencies can be scanned recursively.
type packageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]packageLockDep `json:"dependencies,omitempty"`
}

func (s *Scanner) scanLegacyPackageLockDependencies(deps map[string]packageLockDep, lockPath string) {
	for pkgName, dep := range deps {
		s.addLockfileFindingIfCompromised(pkgName, dep.Version, lockPath)
		if len(dep.Dependencies) > 0 {
			s.scanLegacyPackageLockDependencies(dep.Dependencies, lockPath)
		}
	}
}

func (s *Scanner) addLockfileFindingIfCompromised(pkgName, version, lockPath string) {
	if pkgName == "" {
		return
	}
	if !s.isCompromisedPackageVersion(pkgName, version) {
		return
	}
	s.addFinding(report.FindingLockfileCompromised,
		fmt.Sprintf("Lockfile contains compromised package: %s", pkgName),
		lockPath)
	s.log("    [!] LOCKFILE: Compromised package %s in %s", pkgName, lockPath)
}

// packageNameFromPackageLockPath extracts the package name from an npm v7+
// package-lock "packages" map key, including nested transitive entries.
func packageNameFromPackageLockPath(pkgPath string) string {
	parts := strings.Split(pkgPath, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "node_modules" {
			continue
		}
		if i+1 >= len(parts) {
			return ""
		}
		if strings.HasPrefix(parts[i+1], "@") {
			if i+2 >= len(parts) {
				return ""
			}
			return parts[i+1] + "/" + parts[i+2]
		}
		return parts[i+1]
	}
	return ""
}

// versionFromLockKey extracts a version token from lockfile keys such as
// "name@1.2.3" or "@scope/name@1.2.3(...)" (used by pnpm parsing).
func versionFromLockKey(key, pkgName string) string {
	if pkgName == "" {
		return ""
	}
	key = strings.TrimSpace(strings.TrimSuffix(key, ":"))

	if strings.HasPrefix(key, "@") {
		marker := pkgName + "@"
		if idx := strings.LastIndex(key, marker); idx >= 0 {
			return normalizePackageVersion(key[idx+len(marker):])
		}
		return ""
	}

	if version, ok := strings.CutPrefix(key, pkgName+"@"); ok {
		return normalizePackageVersion(version)
	}
	return ""
}

// parseYarnLockHeaderPackages parses a yarn.lock stanza header and returns the
// distinct package names represented by one or more selectors in that header.
func parseYarnLockHeaderPackages(header string) []string {
	seen := make(map[string]bool)
	var pkgs []string
	for _, selector := range strings.Split(header, ",") {
		selector = strings.TrimSpace(strings.Trim(selector, "\""))
		if selector == "" {
			continue
		}
		pkgName := yarnPackageNameFromSelector(selector)
		if pkgName == "" || seen[pkgName] {
			continue
		}
		seen[pkgName] = true
		pkgs = append(pkgs, pkgName)
	}
	return pkgs
}

func yarnPackageNameFromSelector(selector string) string {
	if strings.HasPrefix(selector, "@") {
		parts := strings.SplitN(selector, "@", 3)
		if len(parts) >= 2 {
			return "@" + parts[1]
		}
		return ""
	}
	parts := strings.SplitN(selector, "@", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func (s *Scanner) readPackageVersion(pkgDir string) string {
	data, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		return ""
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return ""
	}
	return normalizePackageVersion(meta.Version)
}

// pathHasDirSegment reports whether path contains segment as a directory/file
// path component (not just as a substring).
func pathHasDirSegment(path, segment string) bool {
	return pathDirSegmentCount(path, segment) > 0
}

// pathDirSegmentCount counts exact path components named segment.
func pathDirSegmentCount(path, segment string) int {
	if segment == "" {
		return 0
	}
	normalized := filepath.ToSlash(filepath.Clean(path))
	count := 0
	for _, part := range strings.Split(normalized, "/") {
		if part == segment {
			count++
		}
	}
	return count
}
