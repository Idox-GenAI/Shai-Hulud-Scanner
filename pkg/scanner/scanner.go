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
	"time"

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
		CacheFile:  "./compromised-packages-cache.txt",
		Output:     os.Stdout,
	}
}

// Scanner performs malware detection scans.
type Scanner struct {
	config           *Config
	report           *report.Report
	compromisedPkgs  map[string]bool            // unscoped packages
	compromisedScope map[string]map[string]bool // scoped packages: scope -> name -> true
	scopes           map[string]bool
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
		scopes:           make(map[string]bool),
	}
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

	s.logSection("Scanning for known Shai-Hulud artifact files")
	s.scanMaliciousFiles()

	s.logSection("Checking for TruffleHog installation")
	s.scanTrufflehog()

	if !s.config.FilesOnly {
		s.logSection("Scanning for suspicious git branches and remotes")
		s.scanGit()

		s.logSection("Scanning GitHub Actions workflows")
		s.scanWorkflows()

		s.logSection("Checking cloud credential files")
		s.scanCredentials()

		if s.config.ScanMode == ScanModeFull {
			s.logSection("Checking for self-hosted runners")
			s.scanRunners()
		} else {
			s.log("[Quick] Skipping self-hosted runner scan (use --mode full)")
		}

		s.logSection("Scanning postinstall hooks")
		s.scanHooks()

		s.logSection("Hash-based malware detection")
		s.scanHashes()

		if s.config.ScanMode == ScanModeFull {
			s.logSection("Checking for migration suffix attack")
			s.scanMigrationSuffix()
		} else {
			s.log("[Quick] Skipping migration suffix scan (use --mode full)")
		}
	}

	if s.config.ScanMode == ScanModeFull {
		s.logSection("Scanning for suspicious env+exfil patterns")
		s.scanEnvPatterns()
	} else {
		s.log("[Quick] Skipping env+exfil pattern scan (use --mode full)")
	}

	s.report.SetDuration(time.Since(startTime))
	return s.report, nil
}

func (s *Scanner) log(format string, args ...interface{}) {
	fmt.Fprintf(s.config.Output, format+"\n", args...)
}

func (s *Scanner) logSection(title string) {
	fmt.Fprintf(s.config.Output, "\n---- %s ----\n", title)
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

	// Save to cache
	if len(allPackages) > 0 && s.config.CacheFile != "" {
		s.saveCacheFile(allPackages)
	}

	// Parse packages
	for _, pkg := range allPackages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" || strings.HasPrefix(pkg, "#") {
			continue
		}
		// Extract first token (handle lines with multiple fields)
		token := strings.Fields(pkg)[0]
		token = strings.Trim(token, ",;|")

		if strings.HasPrefix(token, "@") && strings.Contains(token, "/") {
			// Scoped package
			parts := strings.SplitN(token, "/", 2)
			scope := parts[0]
			name := parts[1]
			if s.compromisedScope[scope] == nil {
				s.compromisedScope[scope] = make(map[string]bool)
			}
			s.compromisedScope[scope][name] = true
			s.scopes[scope] = true
		} else {
			s.compromisedPkgs[token] = true
		}
	}

	return nil
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

func (s *Scanner) saveCacheFile(packages []string) {
	f, err := os.Create(s.config.CacheFile)
	if err != nil {
		return
	}
	defer f.Close()

	for _, pkg := range packages {
		fmt.Fprintln(f, pkg)
	}
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
						s.report.AddFinding(report.FindingNodeModules, fullName, filepath.Join(childPath, pkgName))
						s.log("    [!] FOUND: %s at %s", fullName, nm)
					}
				}
			} else {
				// Unscoped package
				if s.compromisedPkgs[name] {
					s.report.AddFinding(report.FindingNodeModules, name, childPath)
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
		// Check unscoped
		if s.compromisedPkgs[name] {
			s.report.AddFinding(report.FindingNpmCache, name, path)
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
					s.report.AddFinding(report.FindingNpmCache, fullName, filepath.Join(path, sub.Name()))
					s.log("    [!] FOUND in cache: %s", fullName)
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

		if s.config.ScanMode == ScanModeQuick {
			// Quick mode: check root and .github/workflows only
			for _, fname := range ioc.MaliciousFileNames {
				fpath := filepath.Join(root, fname)
				if _, err := os.Stat(fpath); err == nil {
					s.report.AddFinding(report.FindingFileArtefact, fname, fpath)
					s.log("    [!] FOUND: %s at %s", fname, root)
				}

				wfPath := filepath.Join(root, ".github", "workflows", fname)
				if _, err := os.Stat(wfPath); err == nil {
					s.report.AddFinding(report.FindingFileArtefact, fname, wfPath)
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
					s.report.AddFinding(report.FindingFileArtefact, d.Name(), path)
					s.log("    [!] FOUND: %s at %s", d.Name(), filepath.Dir(path))
				}
				return nil
			})
		}
	}
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
		for _, line := range strings.Split(branches, "\n") {
			branch := strings.TrimSpace(line)
			branch = strings.TrimPrefix(branch, "* ")
			if ioc.ContainsSuspiciousBranchPattern(branch) {
				s.report.AddFinding(report.FindingGitBranch, "Branch: "+branch, repoDir)
			}
		}
	}

	// Check remotes
	cmd = exec.Command("git", "-C", repoDir, "remote", "-v")
	output, err = cmd.Output()
	if err == nil {
		remotes := string(output)
		if strings.Contains(strings.ToLower(remotes), "shai-hulud") {
			s.report.AddFinding(report.FindingGitRemote, "Remote contains 'Shai-Hulud'", repoDir)
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
						s.report.AddFinding(report.FindingWorkflowPattern, "Suspicious workflow name: "+name, wfPath)
						s.log("    [!] SUSPICIOUS workflow: %s", wfPath)
					}

					// Check workflow content
					content, err := os.ReadFile(wfPath)
					if err != nil {
						continue
					}
					if pattern, found := ioc.ContainsSuspiciousWorkflowPattern(string(content)); found {
						s.report.AddFinding(report.FindingWorkflowContent, "Workflow contains: "+pattern, wfPath)
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
			fullPath := filepath.Join(root, credPath)
			if _, err := os.Stat(fullPath); err == nil {
				s.report.AddFinding(report.FindingCredentialFile, credPath, fullPath)
			}
		}

		if s.config.ScanMode == ScanModeFull {
			// Find all .env* files
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip node_modules
				if strings.Contains(path, "node_modules") {
					return nil
				}
				if strings.HasPrefix(d.Name(), ".env") {
					s.report.AddFinding(report.FindingCredentialFile, ".env file", path)
				}
				return nil
			})
		} else {
			// Quick mode: just check root .env
			envPath := filepath.Join(root, ".env")
			if _, err := os.Stat(envPath); err == nil {
				s.report.AddFinding(report.FindingCredentialFile, ".env file", envPath)
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
					s.report.AddFinding(report.FindingMaliciousRunner, "Malicious self-hosted runner 'SHA1HULUD'", path)
					s.log("    [!] CRITICAL: Malicious runner at %s", path)
				} else {
					s.report.AddFinding(report.FindingRunnerInstallation, "Self-hosted runner installation (verify legitimacy)", path)
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
				if strings.Count(path, "node_modules") > 1 {
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
		Scripts map[string]string `json:"scripts"`
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
			s.report.AddFinding(report.FindingPostinstallHook, fmt.Sprintf("Suspicious %s: %s", hookName, pattern), pkgPath)
		}
	}
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
				if strings.Count(path, "node_modules") > 1 {
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
				// Skip node_modules and .d.ts files
				if strings.Contains(path, "node_modules") {
					return nil
				}
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
		s.report.AddFinding(report.FindingMalwareHash, "SHA256 match: "+desc, filePath)
		s.log("    [!!!] MALWARE DETECTED: %s", filePath)
		return
	}

	if desc, found := ioc.IsMaliciousSHA1(sha1Hash); found {
		s.report.AddFinding(report.FindingMalwareHash, "SHA1 match: "+desc, filePath)
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
				s.report.AddFinding(report.FindingMigrationAttack, "Directory ends with -migration", path)
			}

			// Check git remotes for -migration
			if d.Name() == ".git" {
				repoDir := filepath.Dir(path)
				cmd := exec.Command("git", "-C", repoDir, "remote", "-v")
				output, err := cmd.Output()
				if err == nil && strings.Contains(strings.ToLower(string(output)), "-migration") {
					s.report.AddFinding(report.FindingMigrationAttack, "Remote URL contains '-migration'", repoDir)
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
		s.report.AddFinding(report.FindingTrufflehog, "TruffleHog in PATH", path)
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
					s.report.AddFinding(report.FindingTrufflehog, "TruffleHog binary", path)
				}

				// Check package.json for trufflehog references
				if name == "package.json" && !strings.Contains(path, "node_modules"+string(filepath.Separator)+"node_modules") {
					content, err := os.ReadFile(path)
					if err == nil && strings.Contains(strings.ToLower(string(content)), "trufflehog") {
						s.report.AddFinding(report.FindingTrufflehogRef, "package.json references trufflehog", path)
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
			if strings.Contains(path, "node_modules") {
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
			hasEnvAccess := false
			hasExfil := false

			for _, pattern := range ioc.EnvAccessPatterns {
				if strings.Contains(strings.ToLower(contentStr), strings.ToLower(pattern)) {
					hasEnvAccess = true
					break
				}
			}

			for _, pattern := range ioc.ExfilPatterns {
				if strings.Contains(strings.ToLower(contentStr), strings.ToLower(pattern)) {
					hasExfil = true
					break
				}
			}

			if hasEnvAccess && hasExfil {
				s.report.AddFinding(report.FindingEnvExfil, "Env access + exfil pattern", path)
				s.log("    [!] SUSPICIOUS env+exfil: %s", path)
			}

			return nil
		})
	}
}
