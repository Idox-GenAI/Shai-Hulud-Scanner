package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shai-hulud-scanner/pkg/config"
	"shai-hulud-scanner/pkg/report"
	"shai-hulud-scanner/pkg/scanner"
	"shai-hulud-scanner/pkg/update"
)

var version = "1.2.5"

const defaultReportName = "ShaiHulud-Scan-Report.txt"

const defaultCacheFileName = "compromised-packages-cache.txt"

const bannerNarrow = `
   ___  _  _   _   ___      _  _ _   _ _    _   _ ___
  / __|| || | /_\ |_ _| ___| || | | | | |  | | | |   \
  \__ \| __ |/ _ \ | | |___| __ | |_| | |__| |_| | |) |
  |___/|_||_/_/ \_\___|    |_||_|\___/|____|\___/|___/

         Supply Chain Malware Detection Scanner
`

func printBanner(banner io.Writer) {
	fmt.Fprintln(banner)
	fmt.Fprint(banner, bannerNarrow)
	fmt.Fprintln(banner)
}

func printUsage() {
	fmt.Println("Shai-Hulud Detection Scanner - Cross-platform npm supply chain malware detector")
	fmt.Println()
	fmt.Println("Usage: shai-hulud-scanner [options] [paths...]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0 - No findings, or only warnings (default behavior)")
	fmt.Println("  1 - High-confidence detections found (known bad packages, IOCs)")
	fmt.Println("  2 - Critical findings (confirmed malware)")
	fmt.Println()
	fmt.Println("Severity Levels:")
	fmt.Println("  critical - Confirmed malware (hash matches, malicious runners)")
	fmt.Println("  high     - Known compromised packages, specific IOC files/patterns")
	fmt.Println("  warning  - Needs review, may be false positive (env patterns, hooks)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  shai-hulud-scanner                          # Quick scan of home directory")
	fmt.Println("  shai-hulud-scanner -mode full               # Full scan of home directory")
	fmt.Println("  shai-hulud-scanner /path/to/project         # Quick scan of specific path")
	fmt.Println("  shai-hulud-scanner -mode full -report scan.txt /projects")
	fmt.Println("  shai-hulud-scanner --strict /path           # Fail on any finding (old behavior)")
	fmt.Println("  shai-hulud-scanner --warn-only /path        # Only fail on high+ severity")
	fmt.Println("  shai-hulud-scanner --config allowlist.json  # Use allowlist configuration")
	fmt.Println("  shai-hulud-scanner --update-check           # Check GitHub releases and download an update")
	fmt.Println()
}

func exitCodeForReport(rpt *report.Report, strict, warnOnly, reportWriteFailed bool) int {
	if rpt == nil {
		if reportWriteFailed {
			return 1
		}
		return 0
	}

	// Critical findings always win.
	if rpt.IsCritical() {
		return 2
	}
	if strict && rpt.HasFindings() {
		return 1
	}
	if rpt.HasHighSeverity() {
		return 1
	}
	if reportWriteFailed {
		return 1
	}
	return 0
}

func main() {
	// Define flags
	var (
		mode        = flag.String("mode", "quick", "Scan mode: quick or full")
		reportPath  = flag.String("report", "./"+defaultReportName, "Report output path")
		cachePath   = flag.String("cache", "", "Path or directory for compromised package cache file (default: system temp dir)")
		noBanner    = flag.Bool("no-banner", false, "Do not print the banner")
		filesOnly   = flag.Bool("files-only", false, "Only scan for malicious files (skip git, npm cache, etc.)")
		strict      = flag.Bool("strict", false, "Strict mode: exit 1 on ANY finding including warnings (old behavior)")
		warnOnly    = flag.Bool("warn-only", false, "Warn-only mode: exit 0 on warnings, only fail on high+ severity findings")
		configPath  = flag.String("config", "", "Path to allowlist configuration file (JSON)")
		updateCheck = flag.Bool("update-check", false, "Check GitHub releases and download a matching update package")
		showHelp    = flag.Bool("help", false, "Show help message")
		showVer     = flag.Bool("V", false, "Show version")
	)

	flag.Usage = printUsage

	flag.Parse()

	// Normalize report path: if a directory is provided, place the report file
	// inside that directory using the default report name.
	resolvedReportPath := *reportPath
	if info, err := os.Stat(resolvedReportPath); err == nil && info.IsDir() {
		resolvedReportPath = filepath.Join(resolvedReportPath, defaultReportName)
	} else {
		// If the path does not currently exist but clearly looks like a directory
		// (for example, ends with a path separator), treat it as a directory and
		// append the default report name. This keeps behavior intuitive when
		// users pass values like "/tmp/" or "./reports/".
		if strings.HasSuffix(resolvedReportPath, string(os.PathSeparator)) {
			resolvedReportPath = filepath.Join(resolvedReportPath, defaultReportName)
		}
	}

	if *showVer {
		fmt.Printf("shai-hulud-scanner version %s\n", version)
		os.Exit(0)
	}

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *updateCheck {
		if err := runUpdateCheck(version); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking for update: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Validate mode
	scanMode := strings.ToLower(*mode)
	if scanMode != "quick" && scanMode != "full" {
		fmt.Fprintf(os.Stderr, "Error: Invalid mode '%s'. Use 'quick' or 'full'.\n", *mode)
		os.Exit(1)
	}

	// Get root paths from remaining arguments or use default
	rootPaths := flag.Args()
	if len(rootPaths) == 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Could not determine home directory: %v\n", err)
			os.Exit(1)
		}
		rootPaths = []string{homeDir}
	}

	if !*noBanner {
		printBanner(os.Stdout)
		fmt.Println("============================================")
		fmt.Println(" Shai-Hulud Dynamic Detection (Go)")
		fmt.Println("============================================")
		fmt.Println()

		if scanMode == "quick" {
			fmt.Println("[*] Scan Mode: QUICK (fast scan, common IOCs)")
			fmt.Println("[*] For comprehensive analysis, use: -mode full")
		} else {
			fmt.Println("[*] Scan Mode: FULL (comprehensive deep scan)")
			fmt.Println("[*] This may take several minutes...")
		}
		fmt.Println()
	}

	// Load allowlist configuration if specified
	var allowlist *config.Allowlist
	if *configPath != "" {
		var err error
		allowlist, err = config.LoadAllowlist(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
		if !*noBanner {
			fmt.Printf("[*] Loaded allowlist configuration from: %s\n", *configPath)
		}
	}

	// Create a scanner configuration, starting from defaults so that
	// features like feed caching are consistently enabled.
	cfg := scanner.DefaultConfig()
	cfg.RootPaths = rootPaths
	cfg.ScanMode = scanner.ScanMode(scanMode)
	cfg.ReportPath = resolvedReportPath
	cfg.NoBanner = *noBanner
	cfg.FilesOnly = *filesOnly
	cfg.Strict = *strict
	cfg.WarnOnly = *warnOnly
	cfg.Allowlist = allowlist
	if *cachePath != "" {
		resolvedCachePath := *cachePath
		if info, err := os.Stat(resolvedCachePath); err == nil && info.IsDir() {
			resolvedCachePath = filepath.Join(resolvedCachePath, defaultCacheFileName)
		} else if strings.HasSuffix(resolvedCachePath, string(os.PathSeparator)) {
			resolvedCachePath = filepath.Join(resolvedCachePath, defaultCacheFileName)
		}
		cfg.CacheFile = resolvedCachePath
	}
	cfg.Output = os.Stdout
	scan := scanner.New(cfg)
	rpt, err := scan.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", err)
		os.Exit(1)
	}

	rpt.PrintSummary(os.Stdout)

	fmt.Println()
	fmt.Printf("[*] Writing detailed report to: %s\n", resolvedReportPath)
	reportWriteFailed := false
	if err := rpt.WriteToFile(resolvedReportPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
		reportWriteFailed = true
	} else {
		fmt.Println("[*] Report written successfully.")
	}

	fmt.Println()
	fmt.Println("============================================")
	fmt.Println(" Scan complete - review the report carefully")
	fmt.Println("============================================")
	fmt.Println()

	os.Exit(exitCodeForReport(rpt, *strict, *warnOnly, reportWriteFailed))
}

func runUpdateCheck(currentVersion string) error {
	ctx, cancel := contextWithTimeout()
	defer cancel()

	result, err := update.NewChecker().CheckAndDownload(ctx, currentVersion)
	if err != nil {
		return err
	}
	if !result.UpdateAvailable {
		fmt.Printf("shai-hulud-scanner is up to date (version %s).\n", result.CurrentVersion)
		return nil
	}

	fmt.Printf("Update available: %s -> %s\n", result.CurrentVersion, result.LatestVersion)
	fmt.Printf("Downloaded %s to: %s\n", result.AssetName, result.DownloadPath)
	if result.ChecksumVerified {
		fmt.Println("Checksum verified.")
	} else {
		fmt.Println("No checksum was available for this asset.")
	}
	fmt.Println("Install the downloaded package using your operating system's package installer.")
	return nil
}

var contextWithTimeout = func() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}
